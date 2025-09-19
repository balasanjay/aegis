package aegis

import (
	"github.com/balasanjay/aegis/internal/impl"
	"simd"
)

type AEAD128x2 struct {
	key [16]byte
}

func NewAEAD128x2(key [16]byte) AEAD128x2 {
	return AEAD128x2{key}
}

func (a AEAD128x2) NonceSize() int {
	return 16
}

func (a AEAD128x2) Overhead() int {
	return 16
}

func (a AEAD128x2) Seal(dst, nonce, plaintext, aad []byte) []byte {
	if len(nonce) != a.NonceSize() {
		panic("nonce is incorrect size")
	}

	ret, tag := sliceForAppend(dst, len(plaintext)+a.Overhead())

	var tagb [16]byte
	ret, tagb = a.DetachedSeal16(ret, nonce, plaintext, aad)

	copy(tag[:], tagb[:])

	return ret
}

func (a AEAD128x2) DetachedSeal16(dst, nonce, plaintext, aad []byte) ([]byte, [16]byte) {
	if len(nonce) != a.NonceSize() {
		panic("nonce is incorrect size")
	}

	ret, _ := sliceForAppend(dst, len(plaintext))
	if len(ret) < len(plaintext) {
		panic("expected len(ret) >= len(plaintext)")
	}
	// TODO: panic if ret and plaintext have inexact overlap.
	// TODO: panic if ret and aad have any overlap.

	state := impl.InitState128x2(simd.LoadUint8x16(&a.key), simd.LoadUint8x16Slice(nonce))

	// Absorb AAD.
	{
		var i int
		for i = 0; i+64 <= len(aad); i += 64 {
			m0 := simd.LoadUint8x32Slice(aad[i : i+32])
			m1 := simd.LoadUint8x32Slice(aad[i+32 : i+64])
			state = impl.UpdateState128x2(state, m0, m1)
		}

		if i < len(aad) {
			var last [64]byte
			copy(last[:], aad[i:])

			m0 := simd.LoadUint8x32Slice(last[0:32])
			m1 := simd.LoadUint8x32Slice(last[32:64])
			state = impl.UpdateState128x2(state, m0, m1)
		}
	}

	// Encrypt blocks.
	{
		var i int
		for i = 0; i+64 <= len(plaintext); i += 64 {
			p0 := simd.LoadUint8x32Slice(plaintext[i : i+32])
			p1 := simd.LoadUint8x32Slice(plaintext[i+32 : i+64])

			var c0, c1 simd.Uint8x32
			state, c0, c1 = impl.Enc128x2(state, p0, p1)

			c0.StoreSlice(ret[i : i+32])
			c1.StoreSlice(ret[i+32 : i+64])
		}

		if i < len(plaintext) {
			var last [64]byte
			copy(last[:], plaintext[i:])

			p0 := simd.LoadUint8x32Slice(last[0:32])
			p1 := simd.LoadUint8x32Slice(last[32:64])

			var c0, c1 simd.Uint8x32
			state, c0, c1 = impl.Enc128x2(state, p0, p1)

			c0.StoreSlice(last[0:32])
			c1.StoreSlice(last[32:64])

			copy(ret[i:len(plaintext)], last[:])
		}
	}

	var tag [16]byte
	impl.Finalize128x2(state, uint64(len(aad)), uint64(len(plaintext)), tag[:])

	return ret, tag
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
