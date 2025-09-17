package impl

import (
	"simd"
)

type State128x2 struct {
	V0, V1, V2, V3, V4, V5, V6, V7 simd.Uint8x32
}

func InitState128x2(key simd.Uint8x16, nonce simd.Uint8x16) State128x2 {
	C0 := simd.LoadUint8x16(&[16]byte{0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62})
	C1 := simd.LoadUint8x16(&[16]byte{0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd})

	S0 := key.Xor(nonce)
	S1 := C1
	S2 := C0
	S3 := C1
	S4 := S0
	S5 := key.Xor(C0)
	S6 := key.Xor(C1)
	S7 := S5

	ctx := [32]byte{
		0:  0x00,
		1:  0x01,
		16: 0x01,
		17: 0x01,
	}
	Ctx := simd.LoadUint8x32(&ctx)

	var state State128x2
	state.V0 = simd.Uint8x32{}.SetLo(S0).SetHi(S0)
	state.V1 = simd.Uint8x32{}.SetLo(S1).SetHi(S1)
	state.V2 = simd.Uint8x32{}.SetLo(S2).SetHi(S2)
	state.V3 = simd.Uint8x32{}.SetLo(S3).SetHi(S3)
	state.V4 = simd.Uint8x32{}.SetLo(S4).SetHi(S4)
	state.V5 = simd.Uint8x32{}.SetLo(S5).SetHi(S5)
	state.V6 = simd.Uint8x32{}.SetLo(S6).SetHi(S6)
	state.V7 = simd.Uint8x32{}.SetLo(S7).SetHi(S7)

	Key := simd.Uint8x32{}.SetLo(key).SetHi(key)
	Nonce := simd.Uint8x32{}.SetLo(nonce).SetHi(nonce)

	for range 10 {
		state.V3 = state.V3.Xor(Ctx)
		state.V7 = state.V7.Xor(Ctx)
		state = UpdateState128x2(state, Nonce, Key)
	}

	return state
}

func UpdateState128x2(state State128x2, M0 simd.Uint8x32, M1 simd.Uint8x32) State128x2 {
	V0 := AESx2(state.V7, state.V0.Xor(M0))
	V1 := AESx2(state.V0, state.V1)
	V2 := AESx2(state.V1, state.V2)
	V3 := AESx2(state.V2, state.V3)
	V4 := AESx2(state.V3, state.V4.Xor(M1))
	V5 := AESx2(state.V4, state.V5)
	V6 := AESx2(state.V5, state.V6)
	V7 := AESx2(state.V6, state.V7)

	return State128x2{V0, V1, V2, V3, V4, V5, V6, V7}
}

func Enc128x2(state State128x2, P0 simd.Uint8x32, P1 simd.Uint8x32) (State128x2, simd.Uint8x32, simd.Uint8x32) {
	Z0 := state.V6.Xor(state.V1).Xor(state.V2.And(state.V3))
	Z1 := state.V2.Xor(state.V5).Xor(state.V6.And(state.V7))

	state = UpdateState128x2(state, P0, P1)
	C0 := P0.Xor(Z0)
	C1 := P1.Xor(Z1)

	return state, C0, C1
}

func Dec128x2(state State128x2, C0 simd.Uint8x32, C1 simd.Uint8x32) (State128x2, simd.Uint8x32, simd.Uint8x32) {
	Z0 := state.V6.Xor(state.V1).Xor(state.V2.And(state.V3))
	Z1 := state.V2.Xor(state.V5).Xor(state.V6.And(state.V7))

	P0 := C0.Xor(Z0)
	P1 := C1.Xor(Z1)
	state = UpdateState128x2(state, P0, P1)
	return state, P0, P1
}

func DecPartial128x2(state State128x2, c [64]byte, clen int) (State128x2, [64]byte) {
	if clen <= 0 || clen >= 64 {
		panic("cn out of range")
	}

	Z0 := state.V6.Xor(state.V1).Xor(state.V2.And(state.V3))
	Z1 := state.V2.Xor(state.V5).Xor(state.V6.And(state.V7))

	C0 := simd.LoadUint8x32Slice(c[0:32])
	C1 := simd.LoadUint8x32Slice(c[32:64])

	P0 := C0.Xor(Z0)
	P1 := C1.Xor(Z1)

	// Zero-out any plaintext bytes after the ciphertext length.
	var plaintext [64]byte
	P0.StoreSlice(plaintext[0:32])
	P1.StoreSlice(plaintext[32:64])
	clear(plaintext[clen:])

	P0 = simd.LoadUint8x32Slice(plaintext[0:32])
	P1 = simd.LoadUint8x32Slice(plaintext[32:64])
	state = UpdateState128x2(state, P0, P1)
	return state, plaintext
}

func Finalize128x2(state State128x2, adlen, msglen uint64, tagout []byte) {
	{
		t0 := simd.LoadUint64x2(&[2]uint64{adlen, msglen}).AsUint8x16()
		t1 := simd.Uint8x32{}.SetLo(t0).SetHi(t0).Xor(state.V2)

		for range 7 {
			state = UpdateState128x2(state, t1, t1)
		}
	}

	if len(tagout) == 16 {
		v01 := state.V0.Xor(state.V1)
		v23 := state.V2.Xor(state.V3)
		v45 := state.V4.Xor(state.V5)
		v06 := v01.Xor(v23).Xor(v45).Xor(state.V6)
		v06.GetLo().Xor(v06.GetHi()).StoreSlice(tagout)
	} else if len(tagout) == 32 {
		v01 := state.V0.Xor(state.V1)
		v23 := state.V2.Xor(state.V3)
		v45 := state.V4.Xor(state.V5)
		v67 := state.V6.Xor(state.V7)

		v03 := v01.Xor(v23)
		v03.GetLo().Xor(v03.GetHi()).StoreSlice(tagout[0:16])

		v47 := v45.Xor(v67)
		v47.GetLo().Xor(v47.GetHi()).StoreSlice(tagout[16:32])
	} else {
		panic("tagout must be 16 or 32 bytes")
	}
}

func AESx2(M0 simd.Uint8x32, M1 simd.Uint8x32) simd.Uint8x32 {
	// TODO: do this as a vector op.

	m00 := M0.GetLo()
	m10 := M1.GetLo()
	result0 := AesRoundGeneric(m00, m10)

	m01 := M0.GetHi()
	m11 := M1.GetHi()
	result1 := AesRoundGeneric(m01, m11)

	return simd.Uint8x32{}.SetLo(result0).SetHi(result1)
}
