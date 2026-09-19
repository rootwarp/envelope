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
			r, err := pipeline.Recipient(pipeline.RecipientOptions{IdentityPath: c.String("identity")})
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(a.stdout, r+"\n")
			return err
		},
	})
}
