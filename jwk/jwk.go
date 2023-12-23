package jwk

import (
	"crypto"

	"github.com/jgraeger/jwgo/jwa"
)

type Key interface {
	// Type returns the type of the key (`kty` claim)
	Type() KeyType
	// Alg returns the algorithm of the key (`alg`` claim)
	Algorithm() jwa.KeyAlgorithm
	// ID returns the unique identifier of the key (`kid` claim)
	ID() string
	// Usage returns the usage of the key (`use` claim)
	Usage() KeyUsage
	// Thumbprint returns the JWK thumbprint of the key.
	Thumbprint(hash crypto.Hash) ([]byte, error)
}

const (
	ClaimKty = "kty"
	ClaimAlg = "alg"
	ClaimUse = "use"
	ClaimKid = "kid"
)

type KeyType string

const (
	EC  KeyType = "EC"
	RSA KeyType = "RSA"
	OKP KeyType = "OKP"
)

func (t KeyType) valid() bool {
	switch t {
	case EC, RSA, OKP:
		return true
	default:
		return false
	}
}

// KeyUsage denotes what the key is supposed to be used for.
type KeyUsage string

const (
	Unspecified KeyUsage = ""
	Signing     KeyUsage = "sig"
	Encryption  KeyUsage = "enc"
)

func (u KeyUsage) valid() bool {
	switch u {
	case Signing, Encryption:
		return true
	default:
		return false
	}
}
