package service

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTokenGuardDefaultsNeedExplicitTrust(t *testing.T) {
	c := defaultAccountTokenGuardConfig()
	require.False(t, c.Enabled)
	require.False(t, c.AutoRelogin)
	require.False(t, c.RestoreSchedulable)
	require.Empty(t, c.ProbeEndpoint)
	require.Empty(t, c.ReloginEndpoint)
	require.Empty(t, c.ProbeHeaders)
	require.NoError(t, ValidateAccountTokenGuardConfig(c))
	for _, endpoint := range []string{"https://user:password@example.com/probe", "https://example.com/probe?token=secret", "https://example.com/probe#secret"} {
		c.ProbeEndpoint = endpoint
		require.Error(t, ValidateAccountTokenGuardConfig(c))
	}
}

func TestTokenGuardMasksAndPreservesSecrets(t *testing.T) {
	repo := &accountOpsSettingsStub{}
	s := NewAccountTokenGuardService(repo, nil, nil, nil, nil)
	cfg := defaultAccountTokenGuardConfig()
	cfg.ProbeEndpoint = "https://trusted.example/probe"
	cfg.ReloginEndpoint = "https://trusted.example/login"
	cfg.ProbeHeaders = map[string]string{"Authorization": "Bearer private-probe"}
	cfg.ReloginHeaders = map[string]string{"X-Api-Key": "private-login"}
	cfg.BarkKey = "private-bark"
	cfg.ReloginAccounts = []AccountTokenGuardReloginAccount{{Email: "user@example.com", Password: "private-password", MFASecret: "private-mfa"}}
	saved, err := s.SaveConfig(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "********", saved.BarkKey)
	require.Equal(t, "********", saved.ProbeHeaders["Authorization"])
	require.Equal(t, "********", saved.ReloginAccounts[0].Password)
	saved.IntervalSeconds = 600
	_, err = s.SaveConfig(context.Background(), saved)
	require.NoError(t, err)
	internal, err := s.GetConfig(context.Background())
	require.NoError(t, err)
	require.Equal(t, "private-bark", internal.BarkKey)
	require.Equal(t, "Bearer private-probe", internal.ProbeHeaders["Authorization"])
	require.Equal(t, "private-password", internal.ReloginAccounts[0].Password)
	require.Equal(t, "private-mfa", internal.ReloginAccounts[0].MFASecret)
}

func TestTokenGuardLegacyEndpointsCanBeRepairedWithoutExposingSecrets(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	legacy := defaultAccountTokenGuardConfig()
	legacy.GroupIDs = []int64{}
	legacy.Enabled, legacy.AutoRelogin, legacy.RestoreSchedulable = true, true, true
	legacy.ProbeEndpoint = strings.Replace(server.URL, "http://", "http://private-user:private-password@", 1) + "?token=private-query#private-fragment"
	legacy.ReloginEndpoint = legacy.ProbeEndpoint
	legacy.ProbeHeaders = map[string]string{"Authorization": "private-header"}
	legacy.ReloginAccounts = []AccountTokenGuardReloginAccount{{Email: "owner@example.com", Password: "private-password", MFASecret: "private-mfa"}}
	raw, err := json.Marshal(legacy)
	require.NoError(t, err)
	settings := &accountOpsSettingsStub{raw: string(raw)}
	repo := &tokenGuardTestRepo{states: map[int64]AccountTokenGuardState{}, acquired: true}
	guard := NewAccountTokenGuardService(settings, repo, nil, nil, nil)
	guard.SetEncryptor(tokenGuardTestEncryptor{})
	status, err := guard.Status(context.Background())
	require.NoError(t, err, "administrators must be able to view and repair decodable legacy settings")
	public, err := json.Marshal(status.Config)
	require.NoError(t, err)
	require.NotContains(t, string(public), "private-")
	require.Equal(t, string(raw), settings.raw, "displaying legacy settings must not rewrite them")
	require.False(t, guard.currentConfig().Enabled, "invalid legacy settings must not enter the runtime cache")
	_, err = guard.GetConfig(context.Background())
	require.Error(t, err)
	_, err = guard.RunCycle(context.Background(), true)
	require.Error(t, err)
	_, err = guard.ReloginAccount(context.Background(), 1)
	require.Error(t, err)
	result := guard.probe(context.Background(), legacy, &Account{Credentials: map[string]any{"access_token": "private-token"}})
	require.Equal(t, AccountTokenGuardProbeTransient, result.State)
	_, err = guard.relogin(context.Background(), legacy, legacy.ReloginAccounts[0])
	require.Error(t, err)
	require.Zero(t, requests.Load(), "unvalidated endpoints must never receive credentials")

	replacement := status.Config
	replacement.ProbeEndpoint, replacement.ReloginEndpoint = server.URL, server.URL
	_, err = guard.SaveConfig(context.Background(), replacement)
	require.NoError(t, err)
	saved, err := guard.GetConfig(context.Background())
	require.NoError(t, err)
	legacy.ProbeEndpoint, legacy.ReloginEndpoint = server.URL, server.URL
	require.Equal(t, legacy, saved, "an explicit repair must preserve the existing flags and masked secrets")
}

func TestTokenGuardUnreadableConfigCannotBeReplaced(t *testing.T) {
	for _, raw := range []string{"{broken-json", "encrypted:v1:not-valid-ciphertext"} {
		settings := &accountOpsSettingsStub{raw: raw}
		guard := NewAccountTokenGuardService(settings, nil, nil, nil, nil)
		guard.SetEncryptor(tokenGuardTestEncryptor{})
		_, err := guard.Status(context.Background())
		require.Error(t, err)
		_, err = guard.SaveConfig(context.Background(), defaultAccountTokenGuardConfig())
		require.Error(t, err)
		require.Equal(t, raw, settings.raw, "decoding failures must never reset stored secrets")
	}
}
