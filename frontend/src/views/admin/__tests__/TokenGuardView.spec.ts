import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import TokenGuardView from '../ops/TokenGuardView.vue'
import { getTokenGuardStatus, saveTokenGuardConfig, runTokenGuard, reloginTokenGuardAccount } from '@/api/admin/accountTokenGuard'
vi.mock('@/components/layout/AppLayout.vue', () => ({ default: { template: '<main><slot /></main>' } }))
vi.mock('@/components/admin/operations/SmartOpsNav.vue', () => ({ default: { template: '<nav />' } }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))
vi.mock('@/api/admin/accountTokenGuard', () => ({ getTokenGuardStatus: vi.fn(), saveTokenGuardConfig: vi.fn(), runTokenGuard: vi.fn(), reloginTokenGuardAccount: vi.fn() }))
const config = {
  enabled: false, group_ids: [], interval_seconds: 300, probe_endpoint: '', probe_model: 'gpt-6-astra',
  probe_headers: { Authorization: '********' }, probe_timeout_seconds: 30, probe_concurrency: 1,
  max_probe_per_cycle: 10, auto_relogin: false, relogin_endpoint: '', relogin_headers: { 'X-Key': '********' },
  relogin_accounts: [{ email: 'owner@example.com', password: '********', mfa_secret: '********' }],
  restore_schedulable: false, fail_streak_threshold: 3, bark_key: '********', notify_on_fix: false, notify_on_fail: false,
}
beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(getTokenGuardStatus).mockResolvedValue({ config, accounts: [], events: [], runtime: { running: false, last_run: null, last_message: '', stats: {} } } as any)
  vi.mocked(saveTokenGuardConfig).mockImplementation(async value => value)
})
describe('credential guard masked configuration', () => {
  it('preserves masked fields on unrelated saves without automatically probing or logging in', async () => {
    const wrapper = mount(TokenGuardView); await flushPromises()
    expect(wrapper.text()).toContain('tokenGuard.secretMaskHint')
    expect(wrapper.get('input[type="password"]').attributes('autocomplete')).toBe('new-password')
    expect((wrapper.vm as any).draft.probe_endpoint).toBe('')
    expect((wrapper.vm as any).draft.relogin_endpoint).toBe('')
    expect((wrapper.vm as any).dirty).toBe(false)
    ;(wrapper.vm as any).draft.interval_seconds = 600
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(saveTokenGuardConfig).toHaveBeenCalledWith({ ...config, interval_seconds: 600 })
    expect(runTokenGuard).not.toHaveBeenCalled()
    expect(reloginTokenGuardAccount).not.toHaveBeenCalled()
    wrapper.unmount()
  })
  it('allows replacing a masked password while retaining an unchanged MFA secret', async () => {
    const wrapper = mount(TokenGuardView); await flushPromises()
    ;(wrapper.vm as any).reloginText = 'owner@example.com,replacement-password,********'
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(saveTokenGuardConfig).toHaveBeenCalledWith(expect.objectContaining({ relogin_accounts: [{ email: 'owner@example.com', password: 'replacement-password', mfa_secret: '********' }] }))
    wrapper.unmount()
  })
})
