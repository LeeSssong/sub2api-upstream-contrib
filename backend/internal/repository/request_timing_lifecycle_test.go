package repository

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/pkg/requesttiming"
)

type requestTimingCloser interface {
	CloseRequestTiming(context.Context) error
}

func timingCloser(t *testing.T, repo *usageLogRepository) requestTimingCloser {
	t.Helper()
	closer, ok := any(repo).(requestTimingCloser)
	if !ok {
		t.Fatal("request timing repository must support graceful shutdown")
	}
	return closer
}

func TestRequestTimingCloseBeforeFirstWrite(t *testing.T) {
	closer := timingCloser(t, &usageLogRepository{})
	for range 2 {
		if err := closer.CloseRequestTiming(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRequestTimingCloseDrainsQueuedWritesAfterTimeout(t *testing.T) {
	writeStarted, releaseWrite := make(chan struct{}), make(chan struct{})
	var firstWrite, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseWrite) }) }
	defer release()
	matcher := sqlmock.QueryMatcherFunc(func(expected, actual string) error {
		if err := sqlmock.QueryMatcherRegexp.Match(expected, actual); err != nil {
			return err
		}
		firstWrite.Do(func() { close(writeStarted); <-releaseWrite })
		return nil
	})
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(matcher))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { release(); _ = db.Close() }()
	repo := newUsageLogRepositoryWithSQL(nil, db)
	closer := timingCloser(t, repo)
	for i := range 3 {
		mock.ExpectExec("INSERT INTO request_timing_details").
			WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), fmt.Sprintf("client:queued-%d", i), int64(8)).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	for i := range 3 {
		c := requesttiming.New(time.Now(), 0)
		c.Finish(200, false)
		repo.RecordRequestTiming(requesttiming.With(context.Background(), c), fmt.Sprintf("client:queued-%d", i), 8)
		if i == 0 {
			select {
			case <-writeStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("timing writer did not start")
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := closer.CloseRequestTiming(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close with an active write = %v, want deadline exceeded", err)
	}
	release()
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer drainCancel()
	if err := closer.CloseRequestTiming(drainCtx); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRequestTimingCloseRacesWithFinishedCallbacks(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	// Keep the queue under test without a SQL writer so every accepted callback
	// remains observable after concurrent shutdown has completed.
	repo := &usageLogRepository{db: db, timingQueue: make(chan timingWrite, 128)}
	repo.timingOnce.Do(func() {})
	closer := timingCloser(t, repo)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 64 {
		c := requesttiming.New(time.Now(), 0)
		ctx := requesttiming.With(context.Background(), c)
		repo.RecordRequestTiming(ctx, "client:race", 8)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c.Finish(200, false)
			repo.RecordRequestTiming(ctx, "client:late-registration", 8)
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := closer.CloseRequestTiming(context.Background()); err != nil {
				t.Errorf("close: %v", err)
			}
		}()
	}
	late := requesttiming.New(time.Now(), 0)
	lateCtx := requesttiming.With(context.Background(), late)
	repo.RecordRequestTiming(lateCtx, "client:late-finish", 8)
	close(start)
	wg.Wait()
	accepted := len(repo.timingQueue)
	late.Finish(200, false)
	repo.RecordRequestTiming(lateCtx, "client:after-close", 8)
	if got := len(repo.timingQueue); got != accepted {
		t.Fatalf("callbacks added %d writes after shutdown", got-accepted)
	}
	for range accepted {
		<-repo.timingQueue
	}
	select {
	case _, open := <-repo.timingQueue:
		if open {
			t.Fatal("timing queue remained open after shutdown")
		}
	default:
		t.Fatal("timing queue remained open after shutdown")
	}
}
