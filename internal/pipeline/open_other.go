//go:build !unix

package pipeline

import "os"

const readOpenFlags = os.O_RDONLY
