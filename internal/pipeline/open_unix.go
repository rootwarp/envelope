//go:build unix

package pipeline

import (
	"os"
	"syscall"
)

// O_NONBLOCK so a FIFO at a shard path cannot hang restore.
const readOpenFlags = os.O_RDONLY | syscall.O_NONBLOCK
