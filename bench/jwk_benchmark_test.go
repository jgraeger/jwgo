package bench_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jgraeger/jwgo/jwk"
	xjwk "github.com/lestrrat-go/jwx/v2/jwk"
)

func BenchmarkJWK(b *testing.B) {
	b.Run("RSA", func(b *testing.B) {
		rsaKey, err := generateRsaJwk()
		if err != nil {
			b.Fatal(err)
		}
		runJSONBench(b, rsaKey)
	})
}

func runJSONBench(b *testing.B, privkey xjwk.Key) {
	b.Helper()

	pubkey, err := xjwk.PublicKeyOf(privkey)
	if err != nil {
		b.Fatal(err)
	}

	for _, kt := range []struct {
		Name string
		Key  xjwk.Key
	}{
		{Name: "RSAPrivateKey", Key: privkey},
		{Name: "RSAPublicKey", Key: pubkey},
	} {
		key := kt.Key
		b.Run(kt.Name, func(b *testing.B) {
			buf, _ := json.Marshal(key)
			s := string(buf)

			for _, tc := range []Case{
				{
					Name: "jwx/v2/jwk.Parse",
					Test: func(b *testing.B) error {
						_, err := xjwk.Parse(buf)
						return err
					},
				},
				{
					Name: "jwgo/jwk.Parse",
					Test: func(b *testing.B) error {
						_, err := jwk.Parse(buf)
						return err
					},
				},
				{
					Name:      "jwx/v2/jwk.ParseString",
					SkipShort: true,
					Test: func(b *testing.B) error {
						_, err := xjwk.ParseString(s)
						return err
					},
				},
				{
					Name:      "jwgo/jwk.ParseString",
					SkipShort: true,
					Test: func(b *testing.B) error {
						_, err := jwk.ParseString(s)
						return err
					},
				},
			} {
				tc.Run(b)
			}
		})
	}
}

func generateRsaJwk() (xjwk.Key, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	k, err := xjwk.FromRaw(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}

	if err := xjwk.AssignKeyID(k); err != nil {
		return nil, fmt.Errorf("failed to assign key ID: %w", err)
	}
	k.Set(xjwk.KeyUsageKey, "sig")
	k.Set(xjwk.AlgorithmKey, "RS256")

	return k, nil
}
