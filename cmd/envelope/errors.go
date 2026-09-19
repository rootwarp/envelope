package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/urfave/cli/v3"
)

var (
	errUsage      = errors.New("invalid usage")
	errPositional = errors.New("unexpected positional argument")
)

// usageFail writes the reason (if any) and the contract line to stderr.
// exitCode maps the returned error to 2 without printing it again.
func usageFail(stderr io.Writer, contract string, reason error) error {
	if reason != nil {
		fmt.Fprintln(stderr, reason)
	}
	fmt.Fprintln(stderr, strings.TrimSuffix(contract, "\n"))
	if reason == nil {
		return errUsage
	}
	return fmt.Errorf("%w: %w", errUsage, reason)
}

func (a *app) onUsageError(contract string) cli.OnUsageErrorFunc {
	return func(_ context.Context, _ *cli.Command, err error, _ bool) error {
		return usageFail(a.stderr, contract, err)
	}
}

// exitCode is the only exit-code mapping (§9.2).
func exitCode(err error, stderr io.Writer) int {
	var ec cli.ExitCoder
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errUsage):
		return exitUsage
	case errors.As(err, &ec) && ec.ExitCode() == 3:
		// Library "No help topic" echoes the token; print usageAll instead.
		fmt.Fprint(stderr, usageAll)
		return exitUsage
	default:
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
}
