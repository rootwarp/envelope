package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootwarp/envelope/internal/pipeline"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2 // invalid usage

	defaultK = 3
	defaultN = 5

	// AGEDEBUG=plugin tees both protocol directions to stderr, including any PIN.
	ageDebugPluginWarning = "AGEDEBUG=plugin is set; this is unsafe with a real secret because it writes the PIN to stderr"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run is the entire command. It writes only to the injected writers.
func run(args []string, stdout, stderr io.Writer) int {
	return runWith(args, stdout, stderr, nil)
}

func runWith(args []string, stdout, stderr io.Writer, term pipeline.Terminal) int {
	// Restore the default handler as soon as the first signal arrives,
	// not only after runErr returns, so a second Ctrl-C kills a stuck command.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	return exitCode(runErrWith(ctx, args, stdout, stderr, term), stderr)
}

func runErr(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return runErrWith(ctx, args, stdout, stderr, nil)
}

func runErrWith(ctx context.Context, args []string, stdout, stderr io.Writer, term pipeline.Terminal) error {
	// -version is a flag, not a subcommand; branch before dispatch.
	if isVersionArg(args) {
		return printVersion(stdout)
	}
	// Written through the injected writer, never the process streams.
	if os.Getenv("AGEDEBUG") == "plugin" {
		_, _ = io.WriteString(stderr, ageDebugPluginWarning+"\n")
	}
	return newAppWith(stdout, stderr, term).Run(ctx, append([]string{"envelope"}, args...))
}
