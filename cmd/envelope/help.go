package main

import (
	"context"

	"github.com/urfave/cli/v3"
)

func (a *app) helpCommand() *cli.Command {
	return &cli.Command{
		Name:            "help",
		Aliases:         []string{"h"},
		Usage:           summaryHelp,
		HideHelpCommand: true,
		OnUsageError:    a.onUsageError(usageHelp),
		Action: func(ctx context.Context, c *cli.Command) error {
			if c.NArg() == 0 {
				return cli.DefaultShowRootCommandHelp(c.Root())
			}
			name := c.Args().First()
			if c.NArg() > 1 || name == "help" || name == "h" || c.Root().Command(name) == nil {
				return usageFail(a.stderr, usageAll, nil)
			}
			return cli.DefaultShowCommandHelp(ctx, c.Root(), name)
		},
	}
}
