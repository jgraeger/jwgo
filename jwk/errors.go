package jwk

import (
	"errors"
	"fmt"
)

var (
	ErrMalformedKey = errors.New("malformed key")

	ErrUnknownType   = errors.New("unknown key type")
	ErrUnknownUse    = errors.New("unknown key usage")
	ErrMalformedJSON = errors.New("malformed JSON")
)

func unknownKeyTypeErr(kty string) error {
	return fmt.Errorf("%w: %s", ErrUnknownType, kty)
}

func unknownKeyUseErr(use string) error {
	return fmt.Errorf("%w: %s", ErrUnknownUse, use)
}
