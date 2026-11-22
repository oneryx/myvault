package app

import (
	"testing"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func TestDeferredSyncIsPendingAndRetriesOnce(t *testing.T) {
	old := scheduleSyncRetry
	retries := make(chan func(), 4)
	scheduleSyncRetry = func(retry func()) { retries <- retry }
	t.Cleanup(func() { scheduleSyncRetry = old })

	for _, tc := range []struct {
		name      string
		errs      []error
		wantState SyncStatus
		synced    bool
	}{
		{"retry commits", []error{state.ErrSyncDeferred}, SyncIdle, true},
		{"retry deferred too", []error{state.ErrSyncDeferred, state.ErrSyncDeferred}, SyncPending, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newMockVaultService(state.StatusUnlocked)
			app, m, _ := startSecurityApp(t, svc, PlatformHooks{})
			svc.mu.Lock()
			svc.syncErrs, svc.syncCalls = tc.errs, 0
			svc.mu.Unlock()
			var before time.Time
			app.Post(func() { before = m.LastSync.Get(); m.SyncNow(false) })
			app.WaitUntil(2*time.Second, func() bool { return m.SyncState.Get() == SyncPending })
			if !m.LastSync.Get().Equal(before) || !app.Exists("Sync pending") {
				t.Fatal("a deferred sync was reported as synced")
			}
			select {
			case retry := <-retries:
				retry()
			case <-time.After(2 * time.Second):
				t.Fatal("no retry scheduled")
			}
			app.WaitUntil(2*time.Second, func() bool {
				svc.mu.Lock()
				defer svc.mu.Unlock()
				return svc.syncCalls == 2
			})
			app.WaitUntil(2*time.Second, func() bool { return m.SyncState.Get() == tc.wantState })
			app.Settle()
			select {
			case <-retries:
				t.Fatal("a second automatic retry was scheduled")
			default:
			}
			svc.mu.Lock()
			calls := svc.syncCalls
			svc.mu.Unlock()
			if calls != 2 {
				t.Fatalf("sync calls = %d, want exactly one automatic retry", calls)
			}
			if synced := !m.LastSync.Get().Equal(before); synced != tc.synced || m.SyncState.Get() != tc.wantState {
				t.Fatalf("after retry: state=%v synced=%v, want %v/%v", m.SyncState.Get(), synced, tc.wantState, tc.synced)
			}
		})
	}
}
