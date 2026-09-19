package main

import (
	"context"
	"errors"

	"github.com/urfave/cli/v3"
)

func (a *app) configureCompletion(c *cli.Command) {
	c.Hidden = false
	c.HideHelpCommand = true
	c.OnUsageError = a.onUsageError(usageCompletion)
	// One message for missing and unknown shells; the token is never printed.
	c.Action = func(context.Context, *cli.Command) error {
		return usageFail(a.stderr, usageCompletion, errors.New("completion needs one of: bash, zsh, fish"))
	}
	for _, sub := range c.Commands {
		sub.HideHelpCommand = true
		sub.OnUsageError = a.onUsageError(usageCompletion)
		sub.Action = a.noArgs(usageCompletion, sub.Action)
	}
}
