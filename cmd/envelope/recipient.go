package main

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/rootwarp/envelope/internal/pipeline"
)

func (a *app) recipientCommand() *cli.Command {
	return a.newCommand(cmdSpec{
		name:        "recipient",
		summary:     summaryRecipient,
		contract:    usageRecipient,
		description: descriptionRecipient,
		flags:       []cli.Flag{pathFlag("identity", "identity `FILE` from keygen")},
		run: func(_ context.Context, c *cli.Command) error {
			rs, err := pipeline.Recipient(pipeline.RecipientOptions{IdentityPath: c.String("identity"), Terminal: testTerminal})
			if err != nil {
				return err
			}
			for _, r := range rs {
				if _, err := fmt.Fprint(a.stdout, r+"\n"); err != nil {
					return err
				}
			}
			return nil
		},
	})
}
