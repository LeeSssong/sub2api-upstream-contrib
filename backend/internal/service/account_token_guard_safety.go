package service

import (
	"context"
	"errors"
)

// Safety capabilities are optional for read-only repositories but mandatory for
// running the guard. Missing cross-process serialization fails closed.
type AccountTokenGuardCycleLocker interface {
	AcquireTokenGuardLease(context.Context) (release func(), acquired bool, err error)
}
type AccountTokenGuardCredentialWriter interface {
	UpdateCredentialsIfUnchanged(context.Context, *Account, map[string]any) (bool, error)
}
type AccountTokenGuardRecoveryRepository interface {
	MarkTokenGuardAuthFailure(context.Context, *Account) (bool, error)
	RecoverTokenGuardOwnedState(context.Context, *Account) (bool, error)
}

const AccountTokenGuardOwnedError = "token_guard:verified_auth_failure"

func (s *AccountTokenGuardService) acquireLease(ctx context.Context) (func(), error) {
	locker, ok := s.repo.(AccountTokenGuardCycleLocker)
	if !ok {
		return nil, errors.New("凭证守护仓储不支持跨进程互斥")
	}
	release, acquired, err := locker.AcquireTokenGuardLease(ctx)
	if err != nil {
		return nil, errors.New("凭证守护互斥锁获取失败")
	}
	if !acquired {
		return nil, errors.New("另一实例的凭证守护正在运行")
	}
	return release, nil
}
func (s *AccountTokenGuardService) recoverOwnedState(ctx context.Context, account *Account, cfg AccountTokenGuardConfig) bool {
	if !cfg.Enabled || !cfg.RestoreSchedulable {
		return false
	}
	repo, ok := s.repo.(AccountTokenGuardRecoveryRepository)
	if !ok {
		return false
	}
	updated, err := repo.RecoverTokenGuardOwnedState(ctx, account)
	if err == nil && updated && s.invalidator != nil {
		_ = s.invalidator.InvalidateToken(ctx, account)
	}
	return err == nil && updated
}
