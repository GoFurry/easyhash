package easyhash

import "errors"

var (
	ErrInvalidHashFormat    = errors.New("easyhash: invalid hash format")
	ErrUnsupportedAlgorithm = errors.New("easyhash: unsupported algorithm")
)
