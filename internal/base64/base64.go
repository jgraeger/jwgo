package base64

import (
	"encoding/binary"

	"github.com/cristalhq/base64"
)

type Encoding struct {
	*base64.Encoding
}

var (
	StdEncoding    = Encoding{base64.StdEncoding}
	RawStdEncoding = Encoding{base64.RawStdEncoding}
	URLEncoding    = Encoding{base64.URLEncoding}
	RawURLEncoding = Encoding{base64.RawURLEncoding}
)

func (e Encoding) EncodeUInt64ToString(v uint64) string {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, v)

	for i := 0; i < len(data); i++ {
		if data[i] != 0x0 {
			return e.EncodeToString(data[i:])
		}
	}

	return e.EncodeToString([]byte{0x0})
}
