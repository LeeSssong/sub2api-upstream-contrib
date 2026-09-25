//go:build integration

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestTokenGuardPostgresLegacyConfigEncryptsOnlyOnExplicitSave(t *testing.T) {
	ctx := context.Background()
	const key = "account_token_guard_config_v1"
	settings := NewSettingRepository(testEntClient(t))
	previous, err := settings.Get(ctx, key)
	require.True(t, err == nil || errors.Is(err, service.ErrSettingNotFound))
	t.Cleanup(func() {
		if previous != nil {
			require.NoError(t, settings.Set(ctx, key, previous.Value))
		} else {
			require.NoError(t, settings.Delete(ctx, key))
		}
	})
	legacy := service.AccountTokenGuardConfig{
		Enabled: true, GroupIDs: []int64{7}, IntervalSeconds: 600,
		ProbeEndpoint: "https://trusted.example/probe", ProbeModel: "gpt-test",
		ProbeHeaders:        map[string]string{"Authorization": "Bearer legacy-probe-secret"},
		ProbeTimeoutSeconds: 90, ProbeConcurrency: 2, MaxProbePerCycle: 4,
		AutoRelogin: true, ReloginEndpoint: "https://trusted.example/relogin",
		ReloginHeaders:     map[string]string{"X-Key": "legacy-relogin-secret"},
		ReloginAccounts:    []service.AccountTokenGuardReloginAccount{{Email: "owner@example.com", Password: "  legacy password  ", MFASecret: "legacy-mfa-secret"}},
		RestoreSchedulable: true, FailStreakThreshold: 3, BarkKey: "legacy-bark-secret", NotifyOnFix: true, NotifyOnFail: true,
	}
	raw, err := json.Marshal(legacy)
	require.NoError(t, err)
	require.NoError(t, settings.Set(ctx, key, string(raw)))
	before, err := settings.Get(ctx, key)
	require.NoError(t, err)
	encryptor, err := NewAESEncryptor(&config.Config{Totp: config.TotpConfig{EncryptionKey: strings.Repeat("ab", 32)}})
	require.NoError(t, err)
	guard := service.NewAccountTokenGuardService(settings, nil, nil, nil, nil)
	guard.SetEncryptor(encryptor)
	loaded, err := guard.GetConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, legacy, loaded, "safe defaults must not reset explicitly saved configuration")
	afterRead, err := settings.Get(ctx, key)
	require.NoError(t, err)
	require.Equal(t, before.Value, afterRead.Value, "reading legacy plaintext must never rewrite it")
	require.Equal(t, before.UpdatedAt, afterRead.UpdatedAt)

	public, err := guard.SaveConfig(ctx, loaded)
	require.NoError(t, err)
	require.Equal(t, "********", public.ReloginAccounts[0].Password)
	require.Equal(t, "********", public.ReloginAccounts[0].MFASecret)
	require.Equal(t, "********", public.ProbeHeaders["Authorization"])
	require.Equal(t, "********", public.ReloginHeaders["X-Key"])
	require.Equal(t, "********", public.BarkKey)
	stored, err := settings.Get(ctx, key)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(stored.Value, "encrypted:v1:"))
	for _, secret := range []string{"legacy-probe-secret", "legacy-relogin-secret", "legacy password", "legacy-mfa-secret", "legacy-bark-secret"} {
		require.NotContains(t, stored.Value, secret)
	}
	restarted := service.NewAccountTokenGuardService(settings, nil, nil, nil, nil)
	restarted.SetEncryptor(encryptor)
	restored, err := restarted.GetConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, legacy, restored)
	public.IntervalSeconds = 900
	_, err = restarted.SaveConfig(ctx, public)
	require.NoError(t, err)
	restored, err = restarted.GetConfig(ctx)
	require.NoError(t, err)
	legacy.IntervalSeconds = 900
	require.Equal(t, legacy, restored, "an unrelated masked save must preserve credentials and enabled flags")

	beforeFailure, err := settings.GetValue(ctx, key)
	require.NoError(t, err)
	withoutKey := service.NewAccountTokenGuardService(settings, nil, nil, nil, nil)
	_, err = withoutKey.GetConfig(ctx)
	require.Error(t, err)
	_, err = withoutKey.SaveConfig(ctx, legacy)
	require.Error(t, err, "unreadable encrypted settings must not be replaced with defaults")
	afterFailure, err := settings.GetValue(ctx, key)
	require.NoError(t, err)
	restoredBeforeFailure, err := restarted.GetConfig(ctx)
	require.NoError(t, err)
	require.Equal(t, legacy, restoredBeforeFailure)
	require.Equal(t, beforeFailure, afterFailure, "failed decryption must not rewrite persisted settings")
}
