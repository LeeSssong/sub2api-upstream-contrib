package service

import (
	"errors"
	"net/url"
	"strings"
)

const tokenGuardSecretMask = "********"

// Public responses are copies: masking must never change credentials used by workers.
func publicTokenGuardConfig(c AccountTokenGuardConfig) AccountTokenGuardConfig {
	mask := func(v string) string {
		if v != "" {
			return tokenGuardSecretMask
		}
		return ""
	}
	headers := func(h map[string]string) map[string]string {
		out := make(map[string]string, len(h))
		for k, v := range h {
			out[k] = mask(v)
		}
		return out
	}
	c.ProbeEndpoint = publicTokenGuardEndpoint(c.ProbeEndpoint)
	c.ReloginEndpoint = publicTokenGuardEndpoint(c.ReloginEndpoint)
	c.ProbeHeaders = headers(c.ProbeHeaders)
	c.ReloginHeaders = headers(c.ReloginHeaders)
	c.BarkKey = mask(c.BarkKey)
	c.ReloginAccounts = append([]AccountTokenGuardReloginAccount(nil), c.ReloginAccounts...)
	for i := range c.ReloginAccounts {
		c.ReloginAccounts[i].Password = mask(c.ReloginAccounts[i].Password)
		c.ReloginAccounts[i].MFASecret = mask(c.ReloginAccounts[i].MFASecret)
	}
	return c
}

// Legacy endpoints may contain URL credentials. Keep them visibly invalid and
// repairable, but never return their secrets or silently make them runnable.
func publicTokenGuardEndpoint(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return tokenGuardSecretMask
	}
	if parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" {
		return raw
	}
	if parsed.User != nil {
		parsed.User = url.User(tokenGuardSecretMask)
	}
	if parsed.RawQuery != "" {
		parsed.RawQuery = tokenGuardSecretMask
	}
	if parsed.Fragment != "" {
		parsed.Fragment = tokenGuardSecretMask
	}
	return parsed.String()
}

func restoreTokenGuardSecrets(c, previous AccountTokenGuardConfig) AccountTokenGuardConfig {
	restore := func(v, old string) string {
		if v == tokenGuardSecretMask {
			return old
		}
		return v
	}
	headers := func(h, old map[string]string) map[string]string {
		out := make(map[string]string, len(h))
		for k, v := range h {
			prior := ""
			for name, value := range old {
				if strings.EqualFold(name, k) {
					prior = value
					break
				}
			}
			out[k] = restore(v, prior)
		}
		return out
	}
	c.ProbeHeaders = headers(c.ProbeHeaders, previous.ProbeHeaders)
	c.ReloginHeaders = headers(c.ReloginHeaders, previous.ReloginHeaders)
	c.BarkKey = restore(c.BarkKey, previous.BarkKey)
	c.ReloginAccounts = append([]AccountTokenGuardReloginAccount(nil), c.ReloginAccounts...)
	for i := range c.ReloginAccounts {
		prior := AccountTokenGuardReloginAccount{}
		for _, old := range previous.ReloginAccounts {
			if strings.EqualFold(strings.TrimSpace(c.ReloginAccounts[i].Email), old.Email) {
				prior = old
				break
			}
		}
		c.ReloginAccounts[i].Password = restore(c.ReloginAccounts[i].Password, prior.Password)
		c.ReloginAccounts[i].MFASecret = restore(c.ReloginAccounts[i].MFASecret, prior.MFASecret)
	}
	return c
}

const tokenGuardEncryptedPrefix = "encrypted:v1:"

// SetEncryptor must be called during construction before the service is used.
func (s *AccountTokenGuardService) SetEncryptor(e SecretEncryptor) { s.encryptor = e }
func (s *AccountTokenGuardService) encodeConfig(raw string) (string, error) {
	if s.encryptor == nil {
		return raw, nil
	}
	encrypted, err := s.encryptor.Encrypt(raw)
	if err != nil {
		return "", errors.New("凭证守护配置加密失败")
	}
	return tokenGuardEncryptedPrefix + encrypted, nil
}
func (s *AccountTokenGuardService) decodeConfig(raw string) (string, error) {
	if !strings.HasPrefix(raw, tokenGuardEncryptedPrefix) {
		return raw, nil
	}
	if s.encryptor == nil {
		return "", errors.New("凭证守护配置缺少解密器")
	}
	decoded, err := s.encryptor.Decrypt(strings.TrimPrefix(raw, tokenGuardEncryptedPrefix))
	if err != nil {
		return "", errors.New("凭证守护配置解密失败")
	}
	return decoded, nil
}
