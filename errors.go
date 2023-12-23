package jwgo

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidType    = errors.New("invalid type for claim")
	ErrTokenMalformed = errors.New("token is malformed")
	ErrKeyMalformed   = errors.New("key is malformed")
)

// internal errors
var (
	errInvalidSegmentCount = fmt.Errorf("%w: token contains an invalid number of segments", ErrTokenMalformed)
)
