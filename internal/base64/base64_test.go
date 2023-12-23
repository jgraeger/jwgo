package base64_test

import (
	stdb64 "encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/jgraeger/jwgo/internal/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func FuzzEncodeUInt64ToString(f *testing.F) {
	// We use the function for exponents, so we add some fermat numbers
	for _, tc := range []uint64{0, 3, 17, 257, 65537, 4294967297} {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, in uint64) {
		enc := base64.RawURLEncoding.EncodeUInt64ToString(in)

		dec, err := stdb64.RawURLEncoding.DecodeString(enc)
		require.NoError(t, err, "Stdlib is able to decode output")

		aligned := append(make([]byte, 8-len(dec)), dec...)
		assert.Equal(t, in, binary.BigEndian.Uint64(aligned), "decoded output matches input")
	})
}
