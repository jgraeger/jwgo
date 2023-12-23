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
					"alg": "RS256",
					"kty": "RSA",
					"e": "AQAB",
					"use": "sig",
					"kid": "jcnzM5SYcyC8PPztdZ2exBOyk0G_1EBw-ggiWXrHFMc",
					"n": "rZDnqx3JBZ1PoBoU1NCfEGQ5vy8WUP_0xKpCm9GeuEnO3SI_SeA4IU9udUrRPpIzt9fT7zsma7ZRlvdvuQpk-mz1QuQP-wHeKXVoss5bgM5jv1SIfbJdvn6JFJ_I2L6Mh2WgE6huerUt-xnkyuOfO7MEStdySmaydVUWVMA18AYqj3wurL5p97GCFC5knquXoWQXqSXGOsukWqeha3QcaRdh3PuB_2GmBQJwhk5TlrIO_hkadRbwg2M6texucoBWdL-i5G2WYfeQ4lADUz25yTR0jIEzDLNDVW3Z36ANBiCjRTsqsacOe75VisqgOaVP2KnrFDqxsIwSYexNM9aWHQ"
				}`,
				Hash:     crypto.SHA256,
				expected: []byte{189, 81, 246, 217, 240, 77, 160, 53, 172, 255, 163, 10, 111, 223, 82, 198, 46, 64, 14, 236, 199, 110, 66, 69, 227, 26, 211, 155, 238, 166, 20, 33},
			},
			// For the thumbprint calculations, only public key parameters are used.
			// The thumbprint of a pubkey therefore matches the private key
			// {
			// 	Name: "SHA-256 Private Key",
			// 	JWK: `{
			// 		"alg": "RS256",
			// 		"p": "5EXZdUzc7Sij0P9L2QFwI8p9qzy1e4pzSIpBOHJeKb-LZIsXENzjN6u9i2K5EF1b3Z0Ly72WAwwl9HqMaGdKGpzjeV0tX80fekBYABevFaeSbkNPAg6kPcRBhTl5ZmaBAMb8m53mE85esjI1jfisr-hqJd6wPMBaAphSR9JwIOs",
			// 		"kty": "RSA",
			// 		"q": "wqXyExsfB47637IyTb06CqDlQ6A4iAzdCGoFTis4OcuyPgSjYVpHu1zn9lsvhUq9Bzc36sk_0lglCIa74y9SJYqEtNcls9uti4pTuHKAFqzSFHm9Re8nSvlGARN_a1BP6wN4S275Y2pZL1BuRjVGWGWRLyHjEuEnuo9mJXDqoxc",
			// 		"d": "Ahmjw_1LRmcd5IkMQXr4wcEEtdyC_53pP0v0HGCP9BjoiOJ2M5Wj-Ds20fKCz6gDOjFBXj6v-1OsbxA1aN7IVANngFS0IMxn_MZv6uH2V3un11PVhvfWjIyJahd43a6IksbXBgXeuFti4AvzKcVRUu6ambE7r8zIUgUijQn6XRog4aUsjd5wfsL7h58sUH6T4FRpQvdVwpambrG0GlOZfg25c9zarQiEZ-tT9FbO0olF6lWrrOFay6iGbp4h0dlTr8HkJpFbjZQHNNUHFqG3cndlrKX0hiylpFrkHf0qCY6kYLbvcJn9qZD1bHfTtjyFAxeTt08qL5Zna5nfFtDYvQ",
			// 		"e": "AQAB",
			// 		"use": "sig",
			// 		"kid": "jcnzM5SYcyC8PPztdZ2exBOyk0G_1EBw-ggiWXrHFMc",
			// 		"qi": "rQarz3GVlXpfXCJvkNKLJEFgSP3HQqgqcD4Mr69m6TkTqJw0lU20ceXPaDqKQY7gMxTVCyYeNyx462yrkciYcxa4pB-4kDlH6jZQ1S-uMpc9sgaSMwfk_cbxT8FneQraWnMlkdnXRq78RhK38mJ5KS9-pZZMAhgN8IMYE4kRnAE",
			// 		"dp": "DFc2XWANZYjX6lmS6SVpwZWV26cJjKc8ekR3KC0OqCUhzQqz8YZvhjfzpFBu_tJ9P-rYk2gpbvq-JoxlgNNsrymiJpKB_HbjZ8GIwGCHZ51Kjkl3QP43pNsyS5iC1qVd_gPD7knIAXQbrHiIaqdx9oSTEH8MegxQEWnYsOdQhoc",
			// 		"dq": "VnkYmSpUV6xKgbSNqoGlVnFySN_WHYLxczp-juKegPaggfLXjnloIrG8j3KlIuc4IQuD-PddNhpYoXgR4nT0Xp8yI5DtPAEdET_rv6aGhwxR7CzFTFtZrnIdin7Z_ZfZWUPaXlC31FW7t0xZITGrxbuhiznXwlxqpPPt4jZO1xM",
			// 		"n": "rZDnqx3JBZ1PoBoU1NCfEGQ5vy8WUP_0xKpCm9GeuEnO3SI_SeA4IU9udUrRPpIzt9fT7zsma7ZRlvdvuQpk-mz1QuQP-wHeKXVoss5bgM5jv1SIfbJdvn6JFJ_I2L6Mh2WgE6huerUt-xnkyuOfO7MEStdySmaydVUWVMA18AYqj3wurL5p97GCFC5knquXoWQXqSXGOsukWqeha3QcaRdh3PuB_2GmBQJwhk5TlrIO_hkadRbwg2M6texucoBWdL-i5G2WYfeQ4lADUz25yTR0jIEzDLNDVW3Z36ANBiCjRTsqsacOe75VisqgOaVP2KnrFDqxsIwSYexNM9aWHQ"
			// 	}`,
			// 	Hash:     crypto.SHA256,
			// 	expected: MustBase64Decode(t, "jcnzM5SYcyC8PPztdZ2exBOyk0G_1EBw-ggiWXrHFMc"),
			// },
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
