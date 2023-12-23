package jwk_test

import (
	"testing"

	"github.com/jgraeger/jwgo/jwa"
	"github.com/jgraeger/jwgo/jwk"
	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	for _, tt := range []struct {
		name        string
		keyJSON     string
		assertions  func(jwk.Key)
		expectedErr error
	}{
		{
			name: "valid RSA public key",
			keyJSON: `{
				"use": "sig",
				"kty": "RSA",
				"kid": "public:2fbc8e2a-bea4-4e47-81cd-fd83a90fe82d",
				"alg": "RS256",
				"n": "yiE1GUBL3y0EEiIb-VMhHmFMmqr658aDANE9uaY_vwUkYgBCi6xpz8qTLI048XcUop42HXbIHvFYYEA2_OOGh5s4gUA8HQUkcgQa5fAcrGsf1fk-CnkjolDRkTwuWQjf2lUcCw2dCMUPACbRsiQYDoCq6_froSMROoTMDLSj5uvlwp_mf_S4I-tPd7aAlnIn_XEExDT-hq9xRYryBZRSHTuak2Q7YQXi1nOhjvySU3XK4ZaUY06wisI9-f4c_sXnd8Q5XYXAalYkOvEUw8JJi7rhmGNLJai1TIjYBSp1z3fwTOhDWzq-v1xwivKlF8qRtHEnIYAcdsYJo80wRZMY8pWu4t_9dk_n0U1zIfwczeKc486zJFQZ5xkbXnERvEzYwCe03wEv_nDJn33mVnE_1RyGAZFTkLLFojCf0LF1e-8VElVfGNP6TAxUckmCem6n0TRt4dbOitmVKzfKWUbIpxATEywSHFkWAU8MzoDVMZ7htOGdcse1WG1HbPlAMvbWsq9R2Q6AKjBWrwpi64VaZ4ekR-EDF8ImmVtW2abm0ILg38zyVcef2IseDgPJu7sU_uvU6p-_HRCLaxr4qC7nYe9CjO2YVXEvXWDRrPWgfkESPiPnoFOZE1YEGYCGoqJYii57vFR-T6UCG-HUkV9vaLWdKNh-XfxqKfcx7w1aY4c",
				"e": "AQAB"
			}`,
			assertions: func(k jwk.Key) {
				assert.Equal(t, jwk.Signing, k.Usage())
				assert.Equal(t, jwk.RSA, k.Type())
				assert.Equal(t, "public:2fbc8e2a-bea4-4e47-81cd-fd83a90fe82d", k.ID())
				assert.Equal(t, jwa.RS256, k.Algorithm())

				_, isRSAPubKey := k.(*jwk.RSAPublicKey)
				assert.True(t, isRSAPubKey)
			},
		},
	} {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key, err := jwk.ParseString(tc.keyJSON)
			if tc.expectedErr != nil {
				assert.ErrorIs(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
			}

			if tc.assertions != nil {
				tc.assertions(key)
			}
		})
	}
}
