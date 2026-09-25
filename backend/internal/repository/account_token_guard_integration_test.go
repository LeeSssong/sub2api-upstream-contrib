//go:build integration

package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestTokenGuardPostgresCASOwnershipAndLease(t *testing.T) {
	ctx := context.Background()
	repo := newAccountRepositoryWithSQL(testEntClient(t), integrationDB, nil)
	guard := &accountTokenGuardRepository{db: integrationDB}
	a := &service.Account{Name: fmt.Sprintf("guard-cas-%d", time.Now().UnixNano()), Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Status: service.StatusActive, Schedulable: true, Credentials: map[string]any{"access_token": "old", "refresh_token": "refresh", "custom_setting": "keep"}, Extra: map[string]any{}}
	require.NoError(t, repo.Create(ctx, a))
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(ctx, "DELETE FROM scheduler_outbox WHERE account_id=$1", a.ID)
		_, _ = integrationDB.ExecContext(ctx, "DELETE FROM accounts WHERE id=$1", a.ID)
	})
	read := func() *service.Account { fresh, e := repo.GetByID(ctx, a.ID); require.NoError(t, e); return fresh }
	a = read()
	updated, err := guard.UpdateCredentialsIfUnchanged(ctx, a, map[string]any{"access_token": "new", "custom_setting": "overwrite"})
	require.NoError(t, err)
	require.True(t, updated)
	require.Equal(t, "keep", read().GetCredential("custom_setting"))
	updated, err = guard.UpdateCredentialsIfUnchanged(ctx, a, map[string]any{"access_token": "stale"})
	require.NoError(t, err)
	require.False(t, updated)
	require.Equal(t, "new", read().GetCredential("access_token"))
	a = read()
	updated, err = guard.MarkTokenGuardAuthFailure(ctx, a)
	require.NoError(t, err)
	require.True(t, updated)
	a = read()
	require.Equal(t, service.StatusError, a.Status)
	require.False(t, a.Schedulable)
	// Successful credential renewal advances only still-owned revisions.
	updated, err = guard.UpdateCredentialsIfUnchanged(ctx, a, map[string]any{"access_token": "relogin-token"})
	require.NoError(t, err)
	require.True(t, updated)
	a = read()
	// A restarted repository must be able to restore its persisted ownership.
	restarted := &accountTokenGuardRepository{db: integrationDB}
	updated, err = restarted.RecoverTokenGuardOwnedState(ctx, a)
	require.NoError(t, err)
	require.True(t, updated)
	require.True(t, read().Schedulable)
	// Renew ownership, then a manual same-state write must revoke it.
	a = read()
	updated, err = guard.MarkTokenGuardAuthFailure(ctx, a)
	require.NoError(t, err)
	require.True(t, updated)
	a = read()
	require.NoError(t, repo.SetSchedulable(ctx, a.ID, false))
	updated, err = guard.RecoverTokenGuardOwnedState(ctx, a)
	require.NoError(t, err)
	require.False(t, updated)
	updated, err = guard.RecoverTokenGuardOwnedState(ctx, read())
	require.NoError(t, err)
	require.False(t, updated)
	// Credentials may be renewed without taking back manually revoked ownership.
	updated, err = guard.UpdateCredentialsIfUnchanged(ctx, read(), map[string]any{"access_token": "renewed"})
	require.NoError(t, err)
	require.True(t, updated)
	updated, err = guard.RecoverTokenGuardOwnedState(ctx, read())
	require.NoError(t, err)
	require.False(t, updated)
	require.False(t, read().Schedulable)
	// Preexisting quality/legacy errors cannot be claimed even if their text is identical.
	_, err = integrationDB.ExecContext(ctx, "DELETE FROM account_token_guard_ownership WHERE account_id=$1", a.ID)
	require.NoError(t, err)
	updated, err = guard.RecoverTokenGuardOwnedState(ctx, read())
	require.NoError(t, err)
	require.False(t, updated)
	updated, err = guard.MarkTokenGuardAuthFailure(ctx, read())
	require.NoError(t, err)
	require.False(t, updated)
	// Active cooldowns are not touched or converted into guard-owned isolation.
	_, err = integrationDB.ExecContext(ctx, "UPDATE accounts SET status='active', schedulable=true, error_message='', overload_until=NOW()+interval '1 hour', updated_at=clock_timestamp() WHERE id=$1", a.ID)
	require.NoError(t, err)
	updated, err = guard.MarkTokenGuardAuthFailure(ctx, read())
	require.NoError(t, err)
	require.False(t, updated)
	require.NotNil(t, read().OverloadUntil)
	// Even a runtime restriction written without a new revision blocks recovery.
	_, err = integrationDB.ExecContext(ctx, "UPDATE accounts SET overload_until=NULL, updated_at=clock_timestamp() WHERE id=$1", a.ID)
	require.NoError(t, err)
	updated, err = guard.MarkTokenGuardAuthFailure(ctx, read())
	require.NoError(t, err)
	require.True(t, updated)
	a = read()
	_, err = integrationDB.ExecContext(ctx, "UPDATE accounts SET overload_until=NOW()+interval '1 hour' WHERE id=$1", a.ID)
	require.NoError(t, err)
	updated, err = guard.RecoverTokenGuardOwnedState(ctx, a)
	require.NoError(t, err)
	require.False(t, updated)
	require.False(t, read().Schedulable)
	release, locked, err := guard.AcquireTokenGuardLease(ctx)
	require.NoError(t, err)
	require.True(t, locked)
	_, locked, err = restarted.AcquireTokenGuardLease(ctx)
	require.NoError(t, err)
	require.False(t, locked)
	release()
	release, locked, err = restarted.AcquireTokenGuardLease(ctx)
	require.NoError(t, err)
	require.True(t, locked)
	release()
}
