//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// interrupted ends an optional run's staging when a signal comes before
// the provider starts.
type interrupted struct{ sig syscall.Signal }

func (e interrupted) Error() string {
	return fmt.Sprintf("interrupted (%v) before the agent started", e.sig)
}

type stagingKey struct{}

// stage is the context an optional run's staging works under. The first
// signal that would otherwise end airbag (Ctrl-C, Ctrl-\, a hung-up
// terminal, a kill) cancels it, with interrupted as its cause: the
// staging stops where it is and the run records the session stopped,
// not left marked running with no stop or cleanup. executeProvider ends
// the staging once it takes those signals over itself; done ends it in
// any case.
func stage() (ctx context.Context, done func()) {
	ctx, cancel := context.WithCancelCause(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	quit := make(chan struct{})
	var once sync.Once
	end := func() {
		once.Do(func() {
			signal.Stop(sigs)
			close(quit)
		})
	}
	go func() {
		select {
		case sig := <-sigs:
			s, _ := sig.(syscall.Signal)
			cancel(interrupted{s})
		case <-quit:
		}
	}()
	return context.WithValue(ctx, stagingKey{}, end), func() {
		end()
		cancel(nil)
	}
}

// endStaging lets the staging's signals go: the provider takes them now.
func endStaging(ctx context.Context) {
	if end, ok := ctx.Value(stagingKey{}).(func()); ok {
		end()
	}
}

// staged is the staging's interruption, once it has come.
func staged(ctx context.Context) error {
	var e interrupted
	if err := context.Cause(ctx); errors.As(err, &e) {
		return e
	}
	return nil
}

// stagedOr is err, or the interruption that caused it.
func stagedOr(ctx context.Context, err error) error {
	if e := staged(ctx); e != nil {
		return e
	}
	return err
}

// exitCode is the code a run that failed with err ends with: 128 plus
// the signal for one interrupted, as a shell reports it.
func exitCode(err error) int {
	var e interrupted
	if errors.As(err, &e) && e.sig != 0 {
		return 128 + int(e.sig)
	}
	return 1
}
