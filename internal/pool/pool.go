package pool

import (
	"bytes"
	"math/big"
	"sync"
)

var (
	bytesBufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}
	bigIntPool = sync.Pool{
		New: func() any {
			return new(big.Int)
		},
	}
)

func GetBytesBuffer() *bytes.Buffer {
	//nolint:forcetypeassert
	return bytesBufferPool.Get().(*bytes.Buffer)
}

func PutBytesBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bytesBufferPool.Put(buf)
}

func GetBigInt() *big.Int {
	//nolint:forceTypeAssert
	return bigIntPool.Get().(*big.Int)
}

func PutBigInt(i *big.Int) {
	bigIntPool.Put(i.SetInt64(0))
}
