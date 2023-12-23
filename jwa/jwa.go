package jwa

import (
	"fmt"
)

var (
	allKeyAlgorithms = make(map[string]KeyAlgorithm)
)

func init() {
	// Build one map for all algorithms available.
	copyAsKeyAlg(allKeyAlgorithms, allSignatureAlgorithms)
}

func copyAsKeyAlg[T fmt.Stringer](dst map[string]KeyAlgorithm, src map[string]T) {
	for k, v := range src {
		dst[k] = KeyAlgorithm(v.String())
	}
}

type KeyAlgorithm string

func (ka KeyAlgorithm) String() string {
	return string(ka)
}

func (ka KeyAlgorithm) SignatureAlgorithm() (SignatureAlgorithm, bool) {
	sa := SignatureAlgorithm(ka)
	return sa, sa.Valid()
}

func (ka KeyAlgorithm) Valid() bool {
	_, ok := allKeyAlgorithms[string(ka)]
	return ok
}

func KeyAlgorithmFrom[T SignatureAlgorithm | string](v T) (KeyAlgorithm, error) {
	alg := KeyAlgorithm(v)
	if !alg.Valid() {
		return "", fmt.Errorf("invalid key algorithm %q", v)
	}
	return alg, nil
}
