package jwk

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/cristalhq/base64"
	"github.com/goccy/go-json"
	"github.com/jgraeger/jwgo/jwa"
)

const (
	// parseMapSize is the preallocated size of the map used to parse key-specific claims.
	// The biggest key type supported is a RSA private key, which has eight.
	// (p, q, d, e, qi, dp, dq, n)
	parseMapSize = 8
)

func Parse(key []byte) (Key, error) {
	return ParseReader(bytes.NewReader(key))
}

func ParseString(key string) (Key, error) {
	return ParseReader(strings.NewReader(key))
}

func ParseReader(r io.Reader) (Key, error) {
	p, err := parseKeyJSON(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedKey, err)
	} else if p.Alg.String() == "" {
		return nil, fmt.Errorf("%w: %s", ErrMalformedKey, "missing alg claim")
	}

	return p.toKey()
}

type parsedClaims = map[string]string

func getBigIntClaim(claims parsedClaims, c string) (*big.Int, error) {
	i := new(big.Int)
	if err := unmarshalBigIntClaim(claims, c, i); err != nil {
		return nil, err
	}
	return i, nil
}

func unmarshalBigIntClaim(claims parsedClaims, c string, dst *big.Int) error {
	if dst == nil {
		return errors.New("invalid destination pointer")
	}

	s, ok := claims[c]
	if !ok {
		return fmt.Errorf("%w: rsa: %s", ErrMalformedKey, fmt.Sprintf("missing claim `%s`", c))
	}

	sb, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("%w: rsa: failed to decode %s claim: %w", ErrMalformedKey, c, err)
	}

	dst.SetBytes(sb)
	return nil
}

// parsedJWK is used ot hold a header and claims to be converted into a private key
type parsedJWK struct {
	Header
	k parsedClaims
}

func (p parsedJWK) toKey() (Key, error) {
	switch p.Kty {
	case RSA:
		return p.toRSAKey()
	default:
		return nil, fmt.Errorf("key type %s not supported", p.Kty)
	}
}

func parseKeyJSON(r io.Reader) (p parsedJWK, err error) {
	// Initialize parse struct
	p.k = make(map[string]string, parseMapSize)

	dec := json.NewDecoder(r)

	// Read opening brace
	_, err = readNextJSONDelimiter(dec)
	if err != nil {
		return p, fmt.Errorf("%w: %w", ErrMalformedJSON, err)
	}

	// Decode key
	for dec.More() {
		key, val, err := nextStringPair(dec)
		if err != nil {
			return p, err
		}

		switch key {
		case ClaimAlg:
			p.Alg, err = jwa.KeyAlgorithmFrom(val)
			if err != nil {
				return p, err
			}
		case ClaimKty:
			p.Kty = KeyType(val)
			if !p.Kty.valid() {
				return p, unknownKeyTypeErr(val)
			}
		case ClaimUse:
			p.Use = KeyUsage(val)
			if !p.Use.valid() {
				return p, unknownKeyUseErr(val)
			}
		case ClaimKid:
			p.Kid = val
		default:
			p.k[key] = val
		}
	}

	// Read closing brace
	_, err = readNextJSONDelimiter(dec)
	if err != nil {
		return p, fmt.Errorf("%w: %w", ErrMalformedJSON, err)
	}

	return p, nil
}

func readNextJSONDelimiter(dec *json.Decoder) (json.Delim, error) {
	t, err := dec.Token()
	if err != nil {
		return 0, err
	}

	d, ok := t.(json.Delim)
	if !ok {
		return 0, fmt.Errorf("expected delimiter, got %T", t)
	}

	return d, nil
}

func nextStringPair(dec *json.Decoder) (key, val string, err error) {
	key, err = nextStringToken(dec)
	if err != nil {
		return "", "", err
	}

	val, err = nextStringToken(dec)
	if err != nil {
		return "", "", err
	}

	return key, val, nil
}

func nextStringToken(dec *json.Decoder) (string, error) {
	t, err := dec.Token()
	if err != nil {
		return "", err
	}

	s, ok := t.(string)
	if !ok {
		return "", fmt.Errorf("expected string token, got %T", t)
	}

	return s, nil
}
