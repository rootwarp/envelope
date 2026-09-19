package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2 // FR-21

	defaultK = 3
	defaultN = 5
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is the entire command. It writes only to the injected writers. FR-35.
func run(args []string, stdout, stderr io.Writer) int {
	// FR-34. Restore the default handler as soon as the first signal arrives,
	// not only after runErr returns, so a second Ctrl-C kills a stuck command.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	return exitCode(runErr(ctx, args, stdout, stderr), stderr)
}

func runErr(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	// -version is a flag, not a subcommand; branch before dispatch (FR-30, §3.1).
	if isVersionArg(args) {
		return printVersion(stdout)
	}
	return newApp(stdout, stderr).Run(ctx, append([]string{"envelope"}, args...))
}
