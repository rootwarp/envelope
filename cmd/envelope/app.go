package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/rootwarp/envelope/internal/pipeline"
)

// app is one run's writers. Closures capture it so nothing lives at package scope.
type app struct{ stdout, stderr io.Writer }

type cmdSpec struct {
	name, summary, contract, description string
	flags                                []cli.Flag
	run                                  cli.ActionFunc
}

func newApp(stdout, stderr io.Writer) *cli.Command {
	a := &app{stdout: stdout, stderr: stderr}
	return &cli.Command{
		Name:      "envelope",
		Usage:     summaryRoot,
		UsageText: strings.TrimSuffix(usageAll, "\n"),
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "version",
				Local: true, // without Local, split -version is persistent and fails as missing required flags
				Usage: "print version and dependency pins",
			},
		},
		Writer:                          a.stdout,
		ErrWriter:                       a.stderr,
		ExitErrHandler:                  func(context.Context, *cli.Command, error) {},
		HideHelpCommand:                 true,
		EnableShellCompletion:           true,
		ConfigureShellCompletionCommand: a.configureCompletion,
		OnUsageError:                    a.onUsageError(usageAll),
		Action:                          a.rootAction,
		Commands: []*cli.Command{
			a.helpCommand(),
			a.newCommand(cmdSpec{
				name:        "keygen",
				summary:     summaryKeygen,
				contract:    usageKeygen,
				description: descriptionKeygen,
				flags:       []cli.Flag{pathFlag("out", "identity `FILE`")},
				run: func(_ context.Context, c *cli.Command) error {
					return pipeline.Keygen(pipeline.KeygenOptions{IdentityPath: c.String("out")}, a.stderr)
				},
			}),
			a.newCommand(cmdSpec{
				name:        "split",
				summary:     summarySplit,
				contract:    usageSplit,
				description: descriptionSplit,
				flags: []cli.Flag{
					pathFlag("identity", "identity `FILE` from keygen"),
					pathFlag("in", "input `FILE`"),
					pathFlag("out", "output `DIR`"),
					&cli.IntFlag{Name: "k", Value: defaultK, Usage: "shards needed to restore"},
					&cli.IntFlag{Name: "n", Value: defaultN, Usage: "total shards"},
				},
				run: func(ctx context.Context, c *cli.Command) error {
					k, n := c.Int("k"), c.Int("n")
					if err := pipeline.ValidateKN(k, n); err != nil {
						return usageFail(a.stderr, usageSplit, err)
					}
					_, err := pipeline.Split(ctx, pipeline.SplitOptions{
						IdentityPath: c.String("identity"),
						InPath:       c.String("in"),
						OutDir:       c.String("out"),
						K:            k,
						N:            n,
					}, a.stderr)
					return err
				},
			}),
			a.newCommand(cmdSpec{
				name:        "restore",
				summary:     summaryRestore,
				contract:    usageRestore,
				description: descriptionRestore,
				flags: []cli.Flag{
					pathFlag("identity", "identity `FILE` from keygen"),
					pathFlag("in", "shard `DIR`"),
					pathFlag("out", "output `FILE`"),
				},
				run: func(ctx context.Context, c *cli.Command) error {
					_, err := pipeline.Restore(ctx, pipeline.RestoreOptions{
						IdentityPath: c.String("identity"),
						InDir:        c.String("in"),
						OutPath:      c.String("out"),
					}, a.stderr)
					return err
				},
			}),
		},
	}
}

func (a *app) newCommand(s cmdSpec) *cli.Command {
	return &cli.Command{
		Name:            s.name,
		Usage:           s.summary,
		UsageText:       s.contract,
		Description:     s.description,
		Flags:           s.flags,
		HideHelpCommand: true,
		OnUsageError:    a.onUsageError(s.contract),
		Action:          a.noArgs(s.contract, s.run),
	}
}

func (a *app) noArgs(contract string, run cli.ActionFunc) cli.ActionFunc {
	return func(ctx context.Context, c *cli.Command) error {
		if c.NArg() != 0 {
			return usageFail(a.stderr, contract, errPositional)
		}
		return run(ctx, c)
	}
}

func (a *app) rootAction(_ context.Context, c *cli.Command) error {
	if c.NArg() == 0 {
		return usageFail(a.stderr, usageAll, nil)
	}
	var names []string
	for _, cmd := range c.Root().VisibleCommands() {
		for _, name := range cmd.Names() {
			if name == "help" || name == "h" {
				continue // AD-5: never suggest help
			}
			names = append(names, name)
		}
	}
	s := suggest(c.Args().First(), names)
	if s != "" {
		return usageFail(a.stderr, usageAll, fmt.Errorf("did you mean %q?", s))
	}
	return usageFail(a.stderr, usageAll, nil)
}

func pathFlag(name, usage string) cli.Flag {
	return &cli.StringFlag{
		Name:      name,
		Usage:     usage,
		Required:  true,
		TakesFile: true,
		// Required treats -out "" as set.
		Validator: func(s string) error {
			if s == "" {
				return fmt.Errorf("-%s must not be empty", name)
			}
			return nil
		},
	}
}
