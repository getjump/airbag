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

// staging is an optional run's hold on the signals that would otherwise
// end airbag (Ctrl-C, Ctrl-\, a hung-up terminal, a kill) until the
// provider takes them over.
type staging struct {
	cancel context.CancelCauseFunc
	// soft are the user's own, Ctrl-C and Ctrl-\; hard are a hang-up and
	// a kill.
	soft, hard   chan os.Signal
	quit, exited chan struct{}
	once         sync.Once
}

// stage is the context an optional run's staging works under. The first
// of those signals cancels it, with interrupted as its cause: the staging
// stops where it is and the run records the session stopped, not left
// marked running with no stop or cleanup. executeProvider ends the
// staging once it takes the signals over itself; done ends it in any
// case.
func stage() (ctx context.Context, done func()) {
	ctx, cancel := context.WithCancelCause(context.Background())
	st := &staging{cancel: cancel, soft: make(chan os.Signal, 1), hard: make(chan os.Signal, 1), quit: make(chan struct{}), exited: make(chan struct{})}
	signal.Notify(st.soft, os.Interrupt, syscall.SIGQUIT)
	signal.Notify(st.hard, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		defer close(st.exited)
		select {
		case sig := <-st.soft:
			st.interrupt(sig)
		case sig := <-st.hard:
			st.interrupt(sig)
		case <-st.quit:
		}
	}()
	// A hang-up or a kill stays caught until the run has returned, its
	// stop saved: a closed terminal sends its hang-up twice.
	return context.WithValue(ctx, stagingKey{}, st), func() {
		st.end()
		signal.Stop(st.hard)
		cancel(nil)
	}
}

// interrupt stops the staging. A Ctrl-C or Ctrl-\ after it ends airbag,
// should the staging hang.
func (st *staging) interrupt(sig os.Signal) {
	signal.Stop(st.soft)
	s, _ := sig.(syscall.Signal)
	st.cancel(interrupted{s})
}

// end lets the user's signals go: the provider has registered its own.
// A signal the staging got before then, and has not acted on yet, is its
// interruption all the same.
func (st *staging) end() {
	st.once.Do(func() {
		signal.Stop(st.soft)
		close(st.quit)
		<-st.exited
		select {
		case sig := <-st.soft:
			st.interrupt(sig)
		case sig := <-st.hard:
			st.interrupt(sig)
		default:
		}
	})
}

// endStaging ends the staging: the provider takes the signals now.
func endStaging(ctx context.Context) {
	if st, ok := ctx.Value(stagingKey{}).(*staging); ok {
		st.end()
	}
}

// pending is the staging's interruption, or one that reached the
// provider's own signals before it started. The provider registers them
// before the staging ends, so a signal is the staging's, and has
// cancelled it once endStaging returns, or is in the provider's channel:
// either way nothing starts.
func pending(ctx context.Context, sigs <-chan os.Signal) error {
	select {
	case sig := <-sigs:
		s, _ := sig.(syscall.Signal)
		return interrupted{s}
	default:
		return staged(ctx)
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

// failedCode is the code an optional run that failed with err ends with:
// code, or for one interrupted, in the staging or by a signal the
// provider's own channel caught before its start, the signal's.
func failedCode(ctx context.Context, code int, err error) int {
	var e interrupted
	if errors.As(stagedOr(ctx, err), &e) {
		return exitCode(e)
	}
	return code
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
