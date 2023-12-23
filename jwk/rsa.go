package jwk

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/jgraeger/jwgo/internal/base64"
	"github.com/jgraeger/jwgo/internal/pool"
)

type RSAPrivateKey struct {
	Header
	rsa *rsa.PrivateKey
}

func (k RSAPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	return rsaThumbPrint(hash, k.rsa.PublicKey)
}

type RSAPublicKey struct {
	Header
	rsa rsa.PublicKey
}

func (k RSAPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	return rsaThumbPrint(hash, k.rsa)
}

// Interface guards
var (
	_ Key = (*RSAPrivateKey)(nil)
	_ Key = (*RSAPublicKey)(nil)
)

func rsaThumbPrint(hash crypto.Hash, key rsa.PublicKey) ([]byte, error) {
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)

	buf.WriteString(`{"e":"`)
	buf.WriteString(base64.RawURLEncoding.EncodeUInt64ToString(uint64(key.E)))
	buf.WriteString(`","kty":"RSA","n":"`)
	buf.WriteString(base64.RawURLEncoding.EncodeToString(key.N.Bytes()))
	buf.WriteString(`"}`)

	h := hash.New()
	if _, err := buf.WriteTo(h); err != nil {
		return nil, fmt.Errorf("write thumbprint to hash: %w", err)
	}
	return h.Sum(nil), nil
}

func (pk parsedJWK) toRSAKey() (Key, error) {
	pub, err := buildRSAPublicKey(pk.k)
	if err != nil {
		return nil, err
	}

	if !hasPrivateKeyClaims(pk.k) {
		return &RSAPublicKey{
			Header: pk.Header,
			rsa:    pub,
		}, nil
	}

	// If we have at least on private key claim, we treat the key as a private key.
	d, q, p, err := getPrivateKeyParams(pk.k)
	if err != nil {
		return nil, err
	}

	priv := &rsa.PrivateKey{
		PublicKey: pub,
		D:         d,
		Primes:    []*big.Int{p, q},
	}

	// TODO: Make prime precomputation opt-in on the parser API.
	// priv.Precompute()

	return &RSAPrivateKey{
		Header: pk.Header,
		rsa:    priv,
	}, nil
}

func buildRSAPublicKey(claims parsedClaims) (k rsa.PublicKey, err error) {
	n, err := getBigIntClaim(claims, "n")
	if err != nil {
		return k, err
	}

	// The exponent is stored as int64, so we can use a temporary bigint to parse the hexdigest string
	e := pool.GetBigInt()
	defer pool.PutBigInt(e)
	if err := unmarshalBigIntClaim(claims, "e", e); err != nil {
		return k, err
	}

	return rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

func getPrivateKeyParams(claims parsedClaims) (d, q, p *big.Int, err error) {
	d, err = getBigIntClaim(claims, "d")
	if err != nil {
		return nil, nil, nil, err
	}

	q, err = getBigIntClaim(claims, "q")
	if err != nil {
		return nil, nil, nil, err
	}

	p, err = getBigIntClaim(claims, "p")
	if err != nil {
		return nil, nil, nil, err
	}

	return d, q, p, nil
}

var rsaPrivateKeyClaims = []string{"p", "q", "d", "qi", "dp", "dq"}

func hasPrivateKeyClaims(claims parsedClaims) bool {
	for _, claim := range rsaPrivateKeyClaims {
		if _, ok := claims[claim]; ok {
			return true
		}
	}
	return false
}
