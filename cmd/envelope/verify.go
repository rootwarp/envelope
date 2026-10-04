package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/urfave/cli/v3"

	"github.com/rootwarp/envelope/internal/pipeline"
)

func (a *app) verifyCommand() *cli.Command {
	return a.newCommand(cmdSpec{
		name:        "verify",
		summary:     summaryVerify,
		contract:    usageVerify,
		description: descriptionVerify,
		flags: []cli.Flag{
			pathSliceFlag("identity", "identity `FILE` from keygen"),
			pathSliceFlag("in", "shard `DIR`"),
		},
		run: func(ctx context.Context, c *cli.Command) error {
			rep, err := pipeline.Verify(ctx, pipeline.VerifyOptions{
				IdentityPaths: c.StringSlice("identity"),
				InDirs:        c.StringSlice("in"),
				Terminal:      testTerminal,
			}, a.stderr)
			if rep != nil {
				// First, even when err != nil.
				if werr := writeVerifyReport(a.stdout, rep); werr != nil {
					// Join only a real write failure. errors.Join(err, nil)
					// wraps a lone error and changes its identity.
					return errors.Join(err, werr)
				}
			}
			return err
		},
	})
}

func writeVerifyReport(w io.Writer, rep *pipeline.VerifyReport) error {
	sw := &stickyWriter{w: w}
	fmt.Fprintf(sw, "manifest ok: k=%d n=%d\n", rep.K, rep.N)
	for _, s := range rep.Shards {
		fmt.Fprintf(sw, "%s %s\n", s.Name, s.State)
	}
	fmt.Fprintf(sw, "usable %d of %d, need %d\n", rep.Usable, rep.N, rep.K)
	switch {
	case !rep.PayloadChecked:
		fmt.Fprintln(sw, "payload skipped")
	case !rep.PayloadOK:
		fmt.Fprintln(sw, "payload failed")
	default:
		fmt.Fprintf(sw, "payload ok: %d bytes\n", rep.PlaintextLen)
	}
	fmt.Fprintf(sw, "result: %s\n", rep.Result)
	return sw.err
}
