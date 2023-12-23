package jwk

import "github.com/jgraeger/jwgo/jwa"

// Header represents the JWK claims shared by every key type
type Header struct {
	Kty KeyType
	Alg jwa.KeyAlgorithm `json:"alg,omitempty`
	Kid string           `json:"kid,omitempty`
	Use KeyUsage         `json:"use,omitempty`
}

func (h Header) Type() KeyType {
	return h.Kty
}

func (h Header) Algorithm() jwa.KeyAlgorithm {
	return h.Alg
}

func (h Header) ID() string {
	return h.Kid
}

func (h Header) Usage() KeyUsage {
	return h.Use
}
