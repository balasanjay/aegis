package aegis

import (
	"crypto/subtle"
	"errors"
	"simd"
	"slices"

	"github.com/balasanjay/aegis/internal/impl"
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
	dst = slices.Grow(dst, len(plaintext)+a.Overhead())

	var tagb [16]byte
	dst, tagb = a.DetachedSeal16(dst, nonce, plaintext, aad)

	dst = append(dst, tagb[:]...)

	return dst
}

func absorbAad(state impl.State128x2, aad []byte) impl.State128x2 {
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

	return state
}

func (a AEAD128x2) detachedSeal(dst, nonce, plaintext, aad []byte) ([]byte, impl.State128x2) {
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
	state = absorbAad(state, aad)

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

	return ret, state
}

func (a AEAD128x2) DetachedSeal16(dst, nonce, plaintext, aad []byte) ([]byte, [16]byte) {
	ret, state := a.detachedSeal(dst, nonce, plaintext, aad)
	tag := impl.Finalize128x2_16(state, uint64(len(aad)), uint64(len(plaintext)))
	return ret, tag
}

func (a AEAD128x2) DetachedSeal32(dst, nonce, plaintext, aad []byte) ([]byte, [32]byte) {
	ret, state := a.detachedSeal(dst, nonce, plaintext, aad)
	tag := impl.Finalize128x2_32(state, uint64(len(aad)), uint64(len(plaintext)))
	return ret, tag
}

func (a AEAD128x2) detachedOpen(dst, nonce, ciphertext, aad []byte) ([]byte, impl.State128x2) {
	if len(nonce) != a.NonceSize() {
		panic("nonce is incorrect size")
	}

	ret := slices.Grow(dst, len(ciphertext))
	ret = ret[:len(ciphertext)]

	// TODO: panic if ret and ciphertext have inexact overlap.
	// TODO: panic if ret and aad have any overlap.

	state := impl.InitState128x2(simd.LoadUint8x16(&a.key), simd.LoadUint8x16Slice(nonce))
	state = absorbAad(state, aad)

	// Decrypt blocks.
	{
		var i int
		for i = 0; i+64 <= len(ciphertext); i += 64 {
			c0 := simd.LoadUint8x32Slice(ciphertext[i : i+32])
			c1 := simd.LoadUint8x32Slice(ciphertext[i+32 : i+64])

			var p0, p1 simd.Uint8x32
			state, p0, p1 = impl.Dec128x2(state, c0, c1)

			p0.StoreSlice(ret[i : i+32])
			p1.StoreSlice(ret[i+32 : i+64])
		}

		if i < len(ciphertext) {
			var last [64]byte
			copy(last[:], ciphertext[i:])

			state, last = impl.DecPartial128x2(state, last, len(ciphertext)-i)

			copy(ret[i:len(ciphertext)], last[:len(ciphertext)-i])
		}
	}

	return ret, state
}

func (a AEAD128x2) DetachedOpen16(dst, nonce, ciphertext, aad []byte, tag [16]byte) ([]byte, error) {
	ret, state := a.detachedOpen(dst, nonce, ciphertext, aad)

	expectedTag := impl.Finalize128x2_16(state, uint64(len(aad)), uint64(len(ciphertext)))
	if subtle.ConstantTimeCompare(expectedTag[:], tag[:]) != 1 {
		clear(ret[:])
		return nil, errors.New("tag mismatch")
	}
	return ret, nil
}

func (a AEAD128x2) DetachedOpen32(dst, nonce, ciphertext, aad []byte, tag [32]byte) ([]byte, error) {
	ret, state := a.detachedOpen(dst, nonce, ciphertext, aad)

	expectedTag := impl.Finalize128x2_32(state, uint64(len(aad)), uint64(len(ciphertext)))
	if subtle.ConstantTimeCompare(expectedTag[:], tag[:]) != 1 {
		clear(ret[:])
		return nil, errors.New("tag mismatch")
	}
	return ret, nil
}

func (a AEAD128x2) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < a.Overhead() {
		return nil, errors.New("ciphertext too small")
	}

	tag := ([16]byte)(ciphertext[len(ciphertext)-a.Overhead():])
	ciphertext = ciphertext[:len(ciphertext)-a.Overhead()]

	return a.DetachedOpen16(dst, nonce, ciphertext, aad, tag)
}

type Mac128x2 struct {
	key [16]byte
}

func NewMac128x2(key [16]byte) Mac128x2 {
	return Mac128x2{key}
}

func (m Mac128x2) Sum16(nonce []byte, data []byte) [16]byte {
	state := impl.InitState128x2(simd.LoadUint8x16(&m.key), simd.LoadUint8x16Slice(nonce))
	state = absorbAad(state, data)
	return impl.Finalize128x2Mac_16(state, uint64(len(data)))
}

func (m Mac128x2) Sum32(nonce []byte, data []byte) [32]byte {
	state := impl.InitState128x2(simd.LoadUint8x16(&m.key), simd.LoadUint8x16Slice(nonce))
	state = absorbAad(state, data)
	return impl.Finalize128x2Mac_32(state, uint64(len(data)))
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
