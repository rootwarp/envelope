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

func suggest(token string, names []string) string {
	best, bestDist := "", 3
	for _, name := range names {
		if d := levenshtein(token, name); d < bestDist {
			best, bestDist = name, d
		}
	}
	if bestDist > 2 {
		return ""
	}
	return best
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}
