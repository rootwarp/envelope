package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootwarp/envelope/internal/pipeline"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2 // FR-21

	defaultK = 3
	defaultN = 5
)

var errUsage = errors.New("invalid usage")

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

// exitCode is the only exit-code mapping (§9.2).
func exitCode(err error, stderr io.Writer) int {
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errUsage), errors.Is(err, flag.ErrHelp):
		return exitUsage
	default:
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
}

func runErr(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	// -version is a flag, not a subcommand; branch before dispatch (FR-30, §3.1).
	if isVersionArg(args) {
		return printVersion(stdout)
	}
	if len(args) == 0 {
		fmt.Fprint(stderr, usageAll)
		return errUsage
	}
	switch args[0] {
	case "keygen":
		return runKeygen(args[1:], stderr)
	case "split":
		return runSplit(ctx, args[1:], stderr)
	case "restore":
		return runRestore(ctx, args[1:], stderr)
	default:
		fmt.Fprint(stderr, usageAll)
		return errUsage
	}
}

func runKeygen(args []string, stderr io.Writer) error {
	fs := commandFlags("keygen", usageKeygen, stderr)
	var out string
	fs.StringVar(&out, "out", "", "identity file")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := require(fs, out); err != nil {
		return err
	}
	return pipeline.Keygen(pipeline.KeygenOptions{IdentityPath: out}, stderr)
}

func runSplit(ctx context.Context, args []string, stderr io.Writer) error {
	fs := commandFlags("split", usageSplit, stderr)
	var identity, in, out string
	var k, n int
	fs.StringVar(&identity, "identity", "", "identity file")
	fs.StringVar(&in, "in", "", "input file")
	fs.StringVar(&out, "out", "", "output directory")
	fs.IntVar(&k, "k", defaultK, "data shards")
	fs.IntVar(&n, "n", defaultN, "total shards")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := require(fs, identity, in, out); err != nil {
		return err
	}
	if err := pipeline.ValidateKN(k, n); err != nil {
		fmt.Fprintln(stderr, err)
		return errUsage
	}
	_, err := pipeline.Split(ctx, pipeline.SplitOptions{
		IdentityPath: identity,
		InPath:       in,
		OutDir:       out,
		K:            k,
		N:            n,
	}, stderr)
	return err
}

func runRestore(ctx context.Context, args []string, stderr io.Writer) error {
	fs := commandFlags("restore", usageRestore, stderr)
	var identity, in, out string
	fs.StringVar(&identity, "identity", "", "identity file")
	fs.StringVar(&in, "in", "", "shard directory")
	fs.StringVar(&out, "out", "", "output file")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := require(fs, identity, in, out); err != nil {
		return err
	}
	_, err := pipeline.Restore(ctx, pipeline.RestoreOptions{
		IdentityPath: identity,
		InDir:        in,
		OutPath:      out,
	}, stderr)
	return err
}

func commandFlags(name, usage string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, usage)
		fs.PrintDefaults()
	}
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	return nil
}

func require(fs *flag.FlagSet, vals ...string) error {
	for _, v := range vals {
		if v == "" {
			fs.Usage()
			return errUsage
		}
	}
	return nil
}
