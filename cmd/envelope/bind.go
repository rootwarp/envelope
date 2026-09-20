package main

import (
	"context"
	"errors"

	"github.com/urfave/cli/v3"

	"github.com/rootwarp/envelope/internal/pipeline"
)

var errBindFlags = errors.New("bind needs exactly one of -identity/-out, -bundle/-add-recipient, or -bundle/-replace-identity")

func (a *app) bindCommand() *cli.Command {
	return a.newCommand(cmdSpec{
		name:        "bind",
		summary:     summaryBind,
		contract:    usageBind,
		description: descriptionBind,
		flags: []cli.Flag{
			optionalPathSliceFlag("identity", "identity `FILE`"),
			optionalStringSliceFlag("recipient", "public age recipient"),
			optionalPathFlag("bundle", "identity bundle `FILE`"),
			optionalStringSliceFlag("add-recipient", "public age recipient to add"),
			optionalPathSliceFlag("replace-identity", "replacement identity `FILE`"),
			optionalPathFlag("out", "bundle `FILE`"),
		},
		run: a.bindAction,
	})
}

func (a *app) bindAction(ctx context.Context, c *cli.Command) error {
	opts, err := bindOptions(c)
	if err != nil {
		return usageFail(a.stderr, usageBind, err)
	}
	_, err = pipeline.Bind(ctx, opts, a.stderr)
	if err != nil && errors.Is(err, pipeline.ErrBadRecipient) {
		return usageFail(a.stderr, usageBind, err)
	}
	return err
}

func bindOptions(c *cli.Command) (pipeline.BindOptions, error) {
	out := c.String("out")
	identity := c.StringSlice("identity")
	recipients := c.StringSlice("recipient")
	bundle := c.String("bundle")
	add := c.StringSlice("add-recipient")
	replace := c.StringSlice("replace-identity")

	create := out != "" && len(identity) > 0 && bundle == "" && len(add) == 0 && len(replace) == 0
	addMode := bundle != "" && len(add) > 0 && out == "" && len(identity) == 0 && len(replace) == 0 && len(recipients) == 0
	replaceMode := bundle != "" && len(replace) > 0 && out == "" && len(identity) == 0 && len(add) == 0 && len(recipients) == 0

	n := 0
	if create {
		n++
	}
	if addMode {
		n++
	}
	if replaceMode {
		n++
	}
	if n != 1 {
		return pipeline.BindOptions{}, errBindFlags
	}

	opts := pipeline.BindOptions{Terminal: testTerminal}
	switch {
	case create:
		opts.Mode = pipeline.BindCreate
		opts.IdentityPaths = identity
		opts.Recipients = recipients
		opts.OutPath = out
	case addMode:
		opts.Mode = pipeline.BindAddRecipient
		opts.Recipients = add
		opts.BundlePath = bundle
	default:
		opts.Mode = pipeline.BindReplaceIdentity
		opts.IdentityPaths = replace
		opts.BundlePath = bundle
	}
	return opts, nil
}
