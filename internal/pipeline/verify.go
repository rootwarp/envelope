package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
)

type VerifyOptions struct {
	IdentityPaths []string
	InDirs        []string
	Terminal      Terminal
}

type ShardState int

const (
	ShardOK ShardState = iota
	ShardMissing
	ShardCorrupt
)

func (s ShardState) String() string {
	switch s {
	case ShardOK:
		return "ok"
	case ShardMissing:
		return "missing"
	case ShardCorrupt:
		return "corrupt"
	default:
		return fmt.Sprintf("ShardState(%d)", int(s))
	}
}

type VerifyResult int

const (
	VerifyHealthy VerifyResult = iota
	VerifyDegraded
	VerifyDamaged
	VerifyUnrestorable
)

func (r VerifyResult) String() string {
	switch r {
	case VerifyHealthy:
		return "healthy"
	case VerifyDegraded:
		return "degraded"
	case VerifyDamaged:
		return "damaged"
	case VerifyUnrestorable:
		return "unrestorable"
	default:
		return fmt.Sprintf("VerifyResult(%d)", int(r))
	}
}

type ShardStatus struct {
	Name  string // "shard-NN" via shardFileName
	State ShardState
}

// VerifyReport carries counts, names and states only. No field may ever hold
// payload bytes.
type VerifyReport struct {
	K, N           int
	Shards         []ShardStatus // index order, len == N
	Usable         int
	PayloadChecked bool
	PayloadOK      bool
	PlaintextLen   int64 // valid iff PayloadOK
	Result         VerifyResult
}

var ErrDamaged = errors.New("shard set is damaged: at least one shard failed its digest")

func Verify(ctx context.Context, opts VerifyOptions, status io.Writer) (*VerifyReport, error) {
	set, err := openShardSet(ctx, opts.IdentityPaths, opts.InDirs, true, status, opts.Terminal)
	if err != nil {
		return nil, err
	}
	defer set.keys.Zero()

	rep := &VerifyReport{
		K:      set.m.K,
		N:      set.m.N,
		Shards: shardStatuses(set),
		Usable: set.have,
	}

	if err := set.usableErr(); err != nil {
		rep.Result = VerifyUnrestorable
		return rep, err
	}

	ct, err := set.ciphertext()
	if err != nil {
		rep.Result = VerifyUnrestorable
		return rep, err
	}

	var sink countingSink
	n, err := set.keys.DecryptTo(&sink, func() io.Reader {
		return ctxReader(ctx, bytes.NewReader(ct))
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return nil, fmt.Errorf("payload: %w", err)
		}
		rep.PayloadChecked = true
		rep.Result = VerifyUnrestorable
		return rep, fmt.Errorf("payload: %w", err)
	}

	rep.PayloadChecked = true
	rep.PayloadOK = true
	rep.PlaintextLen = n
	if len(set.failed) > 0 {
		rep.Result = VerifyDamaged
		return rep, ErrDamaged
	}
	if len(set.missing) > 0 {
		rep.Result = VerifyDegraded
		return rep, nil
	}
	rep.Result = VerifyHealthy
	return rep, nil
}

func shardStatuses(set *shardSet) []ShardStatus {
	out := make([]ShardStatus, set.m.N)
	for i := 0; i < set.m.N; i++ {
		out[i] = ShardStatus{Name: shardFileName(i), State: ShardOK}
	}
	for _, i := range set.missing {
		out[i].State = ShardMissing
	}
	for _, i := range set.failed {
		out[i].State = ShardCorrupt
	}
	return out
}

// countingSink is Write-only so io.Copy cannot retain plaintext in a pooled ReaderFrom.
type countingSink struct {
	n int64
}

func (c *countingSink) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}
