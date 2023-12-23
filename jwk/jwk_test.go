package jwk_test

import (
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/jgraeger/jwgo/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRSA(t *testing.T) {
	t.Parallel()

	t.Run("Thumbprint", func(t *testing.T) {
		t.Parallel()
		for _, tt := range []struct {
			Name     string
			JWK      string
			Hash     crypto.Hash
			expected []byte
		}{
			{
				Name: "SHA-256 Public Key",
				JWK: `{
					"kty": "RSA",
					"alg": "RS256",
					"e": "AQAB",
					"use": "sig",
					"n": "kMUCGoWr7_6rNzT5THxmHmBQw457ywXFxA9leV815SY9xGXir3KH4JRIm-jBn2k-eQ506RukOakCBldGDL1d4ZVKu7WzxIMScb79X-98BKfj8mS6kdz7gw6T8wCZ82zxjyKv0ePUd8ZaOVQqi3wrUPYa5dJgdO830NBoVf58b31reHEIpQRhEtT0FSQ5SFggieNoaWf6SWmxVKtScQm4Tuh0fyX_wXfjhAs66djFHUOTxJDICcpNmcKCDKU-gxo_NCpn3xZ51FNVShPqknclE05VKkL4iUu_1WBse0e1NeRhvfkuqrd11Ncx7X2QeXewc4w0iVtKmDeTU13ROj76rQ"
				}}`,
				Hash:     crypto.SHA256,
				expected: MustBase64Decode(t, "BapMmDqQvHu4130aySp-GyzAY2AtIW_MKIIBYn-ev6k")},
			// For the thumbprint calculations, only public key parameters are used.
			// The thumbprint of a pubkey therefore matches the private key
			{
				Name: "SHA-256 Private Key",
				JWK: `{
					"alg": "RS256",
					"p": "2XSYMo76V3B0uVypoTsgpigWsKGbxUTA6FeAMXDCeadMLlr5o-NzGZTjfI96r66SDZTQGegYtmoEKw1M0WQowAxPDwpJiimrDpAlEe_mAyEA9fUD6O6E4f9nQHz9kiNTQ0KrdxC-Itd9J4w--jnKI8ns0DI6XWCiZL4fDheXxdc",
					"kty": "RSA",
					"q": "qm4re5J4QEcLhYGRHHnvFTOoGzMMFBXc9qWy0CekjAEbTFEGZcKJ6aM7Z5Q5Yxk5EW0JZL-76otu5nBBwBfP1iMBfNkBMlQnJe23hE1VIsI4sy5JzpOtc1zyXubNoaz1l9buIIUQaBADo-CFJ0kCjsUc2Az2uVrWvePi8dTOKxs",
					"d": "OsfjTMWNxIqRFn9p4gZ4qEjPQjfuR8b2P99IgnmINpzKY55C5p4IUcWjnbpqM8HV3e1ixuu0SL041z5EcRPKtLebepASh-34ZTr5QiTJJFLPGTKRFny1mscmh3ptCAvqIQYigYSSVnexVqm4BJ7ML7ldvocnJxOihCS62H_WIqYaqAmVQOrG6VCBq-QtiuXQP2YaNcO1G4CizWVK3kthYn3n8jXtsca4n9s8eIOZ7V5VemJVZ3MLQEQJHfBFHSorqI6U5a4aGK-hk4m7skgEG4-pMcIPP0SwmKeMSscA-zKk_sTZYWIZUXjNceLZDUrsgAYJ1GtCV5TzyO_RElzXuQ",
					"e": "AQAB",
					"use": "sig",
					"qi": "e7iS_Lbz6hfOse3naZKEaWr5oOK0vXhIALDGINzh3y7kBRg-Jb1MI-wawr9QgyIpxancuDrc9-Is1dqpz0lzlvs8TK8DFNriZGprinLjllECZgN-34RFWwMEB7E6lFEV41Nc7RzABpidEujtnzqTNBlv8-QbLl0PmT21_S48UlM",
					"dp": "Cct-r4hRLm8aUt8hpOmM5u8XVo1w_snCBrUqSQ_TMreebtgaNo-gN57FQG8WD6PFYGc7mG8j7dOIrIfE1gm07DGhvgOwnFCUK-vCP7SWn7101Z9btbpIsgVXGUiIA3Uj4vu1zX8rkVYzhPyEObEwsbv-tsIMbvhTWEZYD8JwS7E",
					"dq": "kR6WL_acJj9YdCnLYjABgFAoCGEDG-cx62NUSyI2XnBiyi0EAYoQ3Lx9TMlNxDAqA8iQgxUv8Zsgp19W3TZpZrEQBzrQZgZ5_zXXWfRvVdWDai8z8Y6V1vGB_4UP-2bHCK-evFoRikp4jwYS20yzvNXipaUEQPg0eiSdjcXid5k",
					"n": "kMUCGoWr7_6rNzT5THxmHmBQw457ywXFxA9leV815SY9xGXir3KH4JRIm-jBn2k-eQ506RukOakCBldGDL1d4ZVKu7WzxIMScb79X-98BKfj8mS6kdz7gw6T8wCZ82zxjyKv0ePUd8ZaOVQqi3wrUPYa5dJgdO830NBoVf58b31reHEIpQRhEtT0FSQ5SFggieNoaWf6SWmxVKtScQm4Tuh0fyX_wXfjhAs66djFHUOTxJDICcpNmcKCDKU-gxo_NCpn3xZ51FNVShPqknclE05VKkL4iUu_1WBse0e1NeRhvfkuqrd11Ncx7X2QeXewc4w0iVtKmDeTU13ROj76rQ"
				}`,
				Hash:     crypto.SHA256,
				expected: MustBase64Decode(t, "BapMmDqQvHu4130aySp-GyzAY2AtIW_MKIIBYn-ev6k"),
			},
			{
				Name: "SHA-1",
				JWK: `{
					"alg": "RS256",
					"kty": "RSA",
					"e": "AQAB",
					"use": "sig",
					"n": "08RNDYVYx72xVTjbsaIr88xOj-Lzsjk_ZJrILNfUhkEZneNOdeWJtw6UMRNSu7gwARQHR6V373Bm1ubP-KguOGx78r4CPDoPMFT5i4WNmGjiOllwfc_KI4YkIgayEUyxbyIZ4JhxpLkn3UvaYmcmSjndHR7Yaydx3TqTarBZiwnm3W71PY-Ufe7t9El83LtAfCyR0erbmx2oJBPQ3o_MPJKi_51PhgaHSENQZjl8yEPinZfevm8qz1CPt4UPiYzWdJ2LSEksMXdus2T3b2z01Jw2K1NWSeSWlqW9nYCrGXXTvHvi7SCGwerDgQUp968Y3YCcmApPnsxO2lllrRUS5w"
				}`,
				Hash:     crypto.SHA1,
				expected: MustBase64Decode(t, "mhvXBuyvZ6RSra7WKjR2ZrTJsL0"),
			},
		} {
			tc := tt
			t.Run(tc.Name, func(t *testing.T) {
				t.Parallel()

				key, err := jwk.ParseString(tc.JWK)
				require.NoError(t, err, "jwk.ParseKey should succeedd")

				tp, err := key.Thumbprint(tc.Hash)
				require.NoError(t, err, "key.Thumbprint should succeed")

				assert.Equal(t, tc.expected, tp, "calculated thumbprint should match the expected value")
			})
		}
	})
}

func MustBase64Decode(t *testing.T, s string) []byte {
	t.Helper()
	res, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64.RawURLEncoding.DecodeString(%q) failed: %s", s, err)
	}
	return res
}
