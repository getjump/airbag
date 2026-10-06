package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrExecutorActive = errors.New("executor shutdown is unconfirmed; session is quarantined (apply, rollback, discard and resume are refused)")

func (s *Session) CheckExecutorStopped() error {
	_, err := os.Lstat(s.executorPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check executor lease: %w", err)
	}
	return fmt.Errorf("session %s: %w", s.ID, ErrExecutorActive)
}

func (s *Session) BeginExecutor() error {
	f, err := os.OpenFile(s.executorPath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create executor lease: %w", err)
	}
	return errors.Join(f.Sync(), f.Close())
}

func (s *Session) EndExecutor() error   { return os.Remove(s.executorPath()) }
func (s *Session) executorPath() string { return filepath.Join(s.Dir, "executor.active") }
