package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type tokenGuardTestRepo struct {
	states   map[int64]AccountTokenGuardState
	marked   int
	deleted  int
	acquired bool
}

func (r *tokenGuardTestRepo) AcquireTokenGuardLease(context.Context) (func(), bool, error) {
	return func() {}, r.acquired, nil
}
func (r *tokenGuardTestRepo) MarkTokenGuardAuthFailure(context.Context, *Account) (bool, error) {
	r.marked++
	return false, nil
}
func (r *tokenGuardTestRepo) RecoverTokenGuardOwnedState(context.Context, *Account) (bool, error) {
	return false, nil
}
func (r *tokenGuardTestRepo) UpsertState(_ context.Context, s AccountTokenGuardState) error {
	r.states[s.AccountID] = s
	return nil
}
func (r *tokenGuardTestRepo) DeleteStatesExcept(context.Context, []int64) error {
	r.deleted++
	return nil
}
func (r *tokenGuardTestRepo) RecordEvent(context.Context, AccountTokenGuardEvent) error { return nil }
func (r *tokenGuardTestRepo) ListEvents(context.Context, int, int) ([]AccountTokenGuardEvent, error) {
	return nil, nil
}
func (r *tokenGuardTestRepo) ListStates(context.Context) ([]AccountTokenGuardState, error) {
	out := []AccountTokenGuardState{}
	for _, s := range r.states {
		out = append(out, s)
	}
	return out, nil
}
func (r *tokenGuardTestRepo) PruneEvents(context.Context, time.Time) error { return nil }

type tokenGuardTestAccounts struct{ items []Account }

func (a *tokenGuardTestAccounts) GetByID(_ context.Context, id int64) (*Account, error) {
	for i := range a.items {
		if a.items[i].ID == id {
			return &a.items[i], nil
		}
	}
	return nil, nil
}
func (a *tokenGuardTestAccounts) ListByGroup(context.Context, int64) ([]Account, error) {
	return a.items, nil
}
func (a *tokenGuardTestAccounts) ListByPlatform(context.Context, string) ([]Account, error) {
	return a.items, nil
}
func (a *tokenGuardTestAccounts) ClearError(context.Context, int64) error { panic("unsafe clear") }
func (a *tokenGuardTestAccounts) SetSchedulable(context.Context, int64, bool) error {
	panic("unsafe restore")
}

func TestTokenGuardCappedSamplesPreserveThresholdAndHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"result","payload":{"error":{"code":"invalid_token","message":"private-token-must-not-appear"}}}`))
	}))
	defer server.Close()
	cfg := defaultAccountTokenGuardConfig()
	cfg.Enabled = true
	cfg.RestoreSchedulable = true
	cfg.FailStreakThreshold = 2
	cfg.MaxProbePerCycle = 1
	cfg.ProbeEndpoint = server.URL
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	repo := &tokenGuardTestRepo{states: map[int64]AccountTokenGuardState{}, acquired: true}
	accounts := &tokenGuardTestAccounts{items: []Account{{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{"access_token": "x"}}, {ID: 2, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{"access_token": "x"}}}}
	svc := NewAccountTokenGuardService(&accountOpsSettingsStub{raw: string(raw)}, repo, accounts, nil, nil)
	for i := 0; i < 3; i++ {
		_, err = svc.RunCycle(context.Background(), true)
		require.NoError(t, err)
	}
	require.Equal(t, 1, repo.marked)
	require.Equal(t, 2, repo.states[1].FailStreak)
	require.Equal(t, 1, repo.states[2].FailStreak)
	require.Zero(t, repo.deleted)
	require.NotContains(t, repo.states[1].ProbeDetail, "private-token")
	repo.acquired = false
	_, err = svc.RunCycle(context.Background(), true)
	require.Error(t, err)
	_, err = svc.ReloginAccount(context.Background(), 1)
	require.Error(t, err)
}

type tokenGuardTestEncryptor struct{}

func (tokenGuardTestEncryptor) Encrypt(s string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(s)), nil
}
func (tokenGuardTestEncryptor) Decrypt(s string) (string, error) {
	b, e := base64.StdEncoding.DecodeString(s)
	return string(b), e
}
func TestTokenGuardEncryptedConfigAndUnmatchedMasks(t *testing.T) {
	repo := &accountOpsSettingsStub{}
	svc := NewAccountTokenGuardService(repo, nil, nil, nil, nil)
	svc.SetEncryptor(tokenGuardTestEncryptor{})
	cfg := defaultAccountTokenGuardConfig()
	cfg.ReloginAccounts = []AccountTokenGuardReloginAccount{{Email: "a@example.com", Password: "  padded secret  ", MFASecret: "mfa-secret"}}
	cfg.BarkKey = "bark-secret"
	cfg.ProbeHeaders = map[string]string{"Authorization": "private-header"}
	public, err := svc.SaveConfig(context.Background(), cfg)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(repo.raw, tokenGuardEncryptedPrefix))
	require.NotContains(t, repo.raw, "secret")
	require.NotContains(t, repo.raw, "private-header")
	restarted := NewAccountTokenGuardService(repo, nil, nil, nil, nil)
	restarted.SetEncryptor(tokenGuardTestEncryptor{})
	private, err := restarted.GetConfig(context.Background())
	require.NoError(t, err)
	require.Equal(t, "  padded secret  ", private.ReloginAccounts[0].Password)
	_, err = restarted.SaveConfig(context.Background(), public)
	require.NoError(t, err)
	public.ReloginAccounts[0].Email = "unknown@example.com"
	_, err = restarted.SaveConfig(context.Background(), public)
	require.Error(t, err)
	withoutKey := NewAccountTokenGuardService(repo, nil, nil, nil, nil)
	_, err = withoutKey.GetConfig(context.Background())
	require.Error(t, err)
}
func TestTokenGuardNeverFollowsCredentialRedirect(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	svc := NewAccountTokenGuardService(nil, nil, nil, nil, nil)
	cfg := defaultAccountTokenGuardConfig()
	cfg.ProbeEndpoint = redirect.URL
	cfg.ReloginEndpoint = redirect.URL
	result := svc.probe(context.Background(), cfg, &Account{Credentials: map[string]any{"access_token": "private"}})
	require.Equal(t, AccountTokenGuardProbeTransient, result.State)
	_, err := svc.relogin(context.Background(), cfg, AccountTokenGuardReloginAccount{Password: "private"})
	require.Error(t, err)
	require.False(t, reached)
}

func TestTokenGuardProviderMessagesAreNotAuthenticationEvidence(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{401, `private bearer token invalid`},
		{200, `{"type":"result","payload":{"error":{"code":"provider_error","message":"invalid_token private-password"}}}`},
		{200, `{"type":"result","payload":{"error":{"code":"invalid_token private-password"}}}`},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		svc := NewAccountTokenGuardService(nil, nil, nil, nil, nil)
		cfg := defaultAccountTokenGuardConfig()
		cfg.ProbeEndpoint = server.URL
		result := svc.probe(context.Background(), cfg, &Account{Credentials: map[string]any{"access_token": "test-token"}})
		require.Equal(t, AccountTokenGuardProbeTransient, result.State)
		require.NotContains(t, result.Detail, "private")
		server.Close()
	}
}
