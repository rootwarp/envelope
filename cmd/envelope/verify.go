package main

import (
	"context"
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
				writeVerifyReport(a.stdout, rep) // first, even when err != nil
			}
			return err
		},
	})
}

func writeVerifyReport(w io.Writer, rep *pipeline.VerifyReport) {
	fmt.Fprintf(w, "manifest ok: k=%d n=%d\n", rep.K, rep.N)
	for _, s := range rep.Shards {
		fmt.Fprintf(w, "%s %s\n", s.Name, s.State)
	}
	fmt.Fprintf(w, "usable %d of %d, need %d\n", rep.Usable, rep.N, rep.K)
	switch {
	case !rep.PayloadChecked:
		fmt.Fprintln(w, "payload skipped")
	case !rep.PayloadOK:
		fmt.Fprintln(w, "payload failed")
	default:
		fmt.Fprintf(w, "payload ok: %d bytes\n", rep.PlaintextLen)
	}
	fmt.Fprintf(w, "result: %s\n", rep.Result)
}
