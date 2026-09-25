package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

type accountTokenGuardRepository struct{ db *sql.DB }

// NewAccountTokenGuardRepository 提供凭证守护的巡检状态与日志存储。
func NewAccountTokenGuardRepository(db *sql.DB) service.AccountTokenGuardRepository {
	return &accountTokenGuardRepository{db: db}
}

func (r *accountTokenGuardRepository) UpsertState(ctx context.Context, state service.AccountTokenGuardState) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO account_token_guard_states(
 account_id,account_name,account_status,schedulable,probe_state,probe_detail,latency_ms,fail_streak,last_probe_at,last_fix_at,last_fix_action,last_fix_result,updated_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
 ON CONFLICT(account_id) DO UPDATE SET
 account_name=EXCLUDED.account_name,account_status=EXCLUDED.account_status,schedulable=EXCLUDED.schedulable,
 probe_state=EXCLUDED.probe_state,probe_detail=EXCLUDED.probe_detail,latency_ms=EXCLUDED.latency_ms,
 fail_streak=EXCLUDED.fail_streak,last_probe_at=EXCLUDED.last_probe_at,
 last_fix_at=COALESCE(EXCLUDED.last_fix_at,account_token_guard_states.last_fix_at),
 last_fix_action=CASE WHEN EXCLUDED.last_fix_at IS NULL THEN account_token_guard_states.last_fix_action ELSE EXCLUDED.last_fix_action END,
 last_fix_result=CASE WHEN EXCLUDED.last_fix_at IS NULL THEN account_token_guard_states.last_fix_result ELSE EXCLUDED.last_fix_result END,
 updated_at=NOW()`,
		state.AccountID, state.AccountName, state.AccountStatus, state.Schedulable, state.ProbeState, state.ProbeDetail,
		state.LatencyMS, state.FailStreak, state.LastProbeAt, state.LastFixAt, state.LastFixAction, state.LastFixResult)
	return err
}

func (r *accountTokenGuardRepository) DeleteStatesExcept(ctx context.Context, accountIDs []int64) error {
	if len(accountIDs) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM account_token_guard_states WHERE NOT (account_id = ANY($1))`, pq.Array(accountIDs))
	return err
}

func (r *accountTokenGuardRepository) RecordEvent(ctx context.Context, event service.AccountTokenGuardEvent) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO account_token_guard_events(account_id,account_name,kind,detail,latency_ms)
 VALUES($1,$2,$3,$4,$5)`, event.AccountID, event.AccountName, event.Kind, event.Detail, event.LatencyMS)
	if err == nil {
		return nil
	}
	return err
}

func (r *accountTokenGuardRepository) ListEvents(ctx context.Context, offset, limit int) ([]service.AccountTokenGuardEvent, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id,account_id,account_name,kind,detail,latency_ms,created_at
 FROM account_token_guard_events ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	events := make([]service.AccountTokenGuardEvent, 0, limit)
	for rows.Next() {
		var event service.AccountTokenGuardEvent
		if err := rows.Scan(&event.ID, &event.AccountID, &event.AccountName, &event.Kind, &event.Detail, &event.LatencyMS, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (r *accountTokenGuardRepository) ListStates(ctx context.Context) ([]service.AccountTokenGuardState, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT account_id,account_name,account_status,schedulable,probe_state,probe_detail,
 latency_ms,fail_streak,last_probe_at,last_fix_at,last_fix_action,last_fix_result,updated_at
 FROM account_token_guard_states ORDER BY account_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	states := make([]service.AccountTokenGuardState, 0, 32)
	for rows.Next() {
		var state service.AccountTokenGuardState
		if err := rows.Scan(&state.AccountID, &state.AccountName, &state.AccountStatus, &state.Schedulable, &state.ProbeState,
			&state.ProbeDetail, &state.LatencyMS, &state.FailStreak, &state.LastProbeAt, &state.LastFixAt, &state.LastFixAction,
			&state.LastFixResult, &state.UpdatedAt); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func (r *accountTokenGuardRepository) PruneEvents(ctx context.Context, before time.Time) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM account_token_guard_events WHERE created_at < $1`, before)
	return err
}

// The transaction-scoped advisory lock is released on rollback, connection loss,
// cancellation, and process exit. It serializes manual and automatic runs.
func (r *accountTokenGuardRepository) AcquireTokenGuardLease(ctx context.Context) (func(), bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	var acquired bool
	if err := tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock(748021390711)`).Scan(&acquired); err != nil {
		_ = tx.Rollback()
		return nil, false, err
	}
	if !acquired {
		_ = tx.Rollback()
		return nil, false, nil
	}
	return func() { _ = tx.Rollback() }, true, nil
}

// Full-snapshot CAS is intentional: any concurrent operator, quality-rule or
// credential change invalidates the probe/relogin observation. Only approved
// token fields are merged; unrelated credential settings stay in the database.
func (r *accountTokenGuardRepository) UpdateCredentialsIfUnchanged(ctx context.Context, expected *service.Account, patch map[string]any) (bool, error) {
	changes := make(map[string]any)
	for _, key := range []string{"access_token", "refresh_token", "id_token", "expires_at", "token_type"} {
		if value, ok := patch[key]; ok {
			changes[key] = value
		}
	}
	after, err := json.Marshal(changes)
	if err != nil {
		return false, err
	}
	return r.mutateTokenGuardAccount(ctx, expected, "credentials = COALESCE(credentials, '{}'::jsonb) || $8::jsonb", "", string(after), false, false)
}

func (r *accountTokenGuardRepository) MarkTokenGuardAuthFailure(ctx context.Context, expected *service.Account) (bool, error) {
	if expected.Status != service.StatusActive || !expected.Schedulable || expected.ErrorMessage != "" {
		return false, nil
	}
	return r.mutateTokenGuardAccount(ctx, expected,
		"status = 'error', schedulable = false, error_message = $8",
		"AND status = 'active' AND schedulable IS TRUE AND COALESCE(error_message,'') = ''"+tokenGuardNoCooldown,
		service.AccountTokenGuardOwnedError, true, false)
}

func (r *accountTokenGuardRepository) RecoverTokenGuardOwnedState(ctx context.Context, expected *service.Account) (bool, error) {
	if expected.Status != service.StatusError || expected.Schedulable || expected.ErrorMessage != service.AccountTokenGuardOwnedError {
		return false, nil
	}
	return r.mutateTokenGuardAccount(ctx, expected,
		"status = 'active', schedulable = true, error_message = $8",
		"AND EXISTS (SELECT 1 FROM account_token_guard_ownership o WHERE o.account_id=accounts.id AND o.account_updated_at=accounts.updated_at)"+tokenGuardNoCooldown,
		"", false, true)
}

const tokenGuardNoCooldown = `
 AND (temp_unschedulable_until IS NULL OR temp_unschedulable_until <= NOW())
 AND (rate_limit_reset_at IS NULL OR rate_limit_reset_at <= NOW())
 AND (overload_until IS NULL OR overload_until <= NOW())
 AND (auto_pause_on_expired IS NOT TRUE OR expires_at IS NULL OR expires_at > NOW())`

// Statement fragments are internal constants. Ownership tracks the exact row
// revision written by this guard, never a free-form error string alone.
func (r *accountTokenGuardRepository) mutateTokenGuardAccount(ctx context.Context, expected *service.Account, setSQL, whereSQL string, value any, claim, release bool) (bool, error) {
	before, err := json.Marshal(expected.Credentials)
	if err != nil {
		return false, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var revision time.Time
	err = tx.QueryRowContext(ctx, `UPDATE accounts SET `+setSQL+`, updated_at=GREATEST(clock_timestamp(),updated_at+interval '1 microsecond')
 WHERE id=$1 AND deleted_at IS NULL AND updated_at=$2 AND credentials=$3::jsonb
 AND status=$4 AND schedulable=$5 AND COALESCE(error_message,'')=$6
 AND platform='openai' AND type='oauth' AND parent_account_id IS NULL AND $7::boolean `+whereSQL+` RETURNING updated_at`,
		expected.ID, expected.UpdatedAt, string(before), expected.Status, expected.Schedulable, expected.ErrorMessage, true, value).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if claim {
		_, err = tx.ExecContext(ctx, `INSERT INTO account_token_guard_ownership(account_id,account_updated_at) VALUES($1,$2)
   ON CONFLICT(account_id) DO UPDATE SET account_updated_at=EXCLUDED.account_updated_at`, expected.ID, revision)
	} else if release {
		_, err = tx.ExecContext(ctx, `DELETE FROM account_token_guard_ownership WHERE account_id=$1`, expected.ID)
	} else {
		// A credential-only update keeps ownership only if no intervening change had
		// already revoked it. Manual writes never renew this revision.
		_, err = tx.ExecContext(ctx, `UPDATE account_token_guard_ownership SET account_updated_at=$1 WHERE account_id=$2 AND account_updated_at=$3`, revision, expected.ID, expected.UpdatedAt)
	}
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO scheduler_outbox(event_type,account_id,payload) VALUES($1,$2,'{}'::jsonb)`, service.SchedulerOutboxEventAccountChanged, expected.ID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
