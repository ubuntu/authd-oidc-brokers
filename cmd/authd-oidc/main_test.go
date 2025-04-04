package main

import (
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type myApp struct {
	done chan struct{}

	runError         bool
	usageErrorReturn bool
	hupReturn        bool
}

func (a *myApp) Run() error {
	<-a.done
	if a.runError {
		return errors.New("Error requested")
	}
	return nil
}

func (a myApp) UsageError() bool {
	return a.usageErrorReturn
}

func (a myApp) Hup() bool {
	return a.hupReturn
}

func (a *myApp) Quit() {
	close(a.done)
}

//nolint:tparallel // Signal handlers tests: subtests can't be parallel
func TestRun(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		runError         bool
		usageErrorReturn bool
		hupReturn        bool
		sendSig          syscall.Signal

		wantReturnCode int
	}{
		"Run_and_exit_successfully":              {},
		"Run_and_return_error":                   {runError: true, wantReturnCode: 1},
		"Run_and_return_usage_error":             {usageErrorReturn: true, runError: true, wantReturnCode: 2},
		"Run_and_usage_error_only_does_not_fail": {usageErrorReturn: true, runError: false, wantReturnCode: 0},

		// Signals handling
		"Send_SIGINT_exits":           {sendSig: syscall.SIGINT},
		"Send_SIGTERM_exits":          {sendSig: syscall.SIGTERM},
		"Send_SIGHUP_without_exiting": {sendSig: syscall.SIGHUP},
		"Send_SIGHUP_with_exit":       {sendSig: syscall.SIGHUP, hupReturn: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			a := myApp{
				done:             make(chan struct{}),
				runError:         tc.runError,
				usageErrorReturn: tc.usageErrorReturn,
				hupReturn:        tc.hupReturn,
			}

			var rc int
			wait := make(chan struct{})
			go func() {
				rc = run(&a)
				close(wait)
			}()

			time.Sleep(100 * time.Millisecond)

			var exited bool
			switch tc.sendSig {
			case syscall.SIGINT:
				fallthrough
			case syscall.SIGTERM:
				err := syscall.Kill(syscall.Getpid(), tc.sendSig)
				require.NoError(t, err, "Teardown: kill should return no error")
				select {
				case <-time.After(50 * time.Millisecond):
					exited = false
				case <-wait:
					exited = true
				}
				require.Equal(t, true, exited, "Expect to exit on SIGINT and SIGTERM")
			case syscall.SIGHUP:
				err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
				require.NoError(t, err, "Teardown: kill should return no error")
				select {
				case <-time.After(50 * time.Millisecond):
					exited = false
				case <-wait:
					exited = true
				}
				// if SIGHUP returns false: do nothing and still wait.
				// Otherwise, it means that we wanted to stop
				require.Equal(t, tc.hupReturn, exited, "Expect to exit only on SIGHUP returning True")
			}

			if !exited {
				a.Quit()
				<-wait
			}

			require.Equal(t, tc.wantReturnCode, rc, "Return expected code")
		})
	}
}
