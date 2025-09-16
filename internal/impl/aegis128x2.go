package impl

import (
	"simd"
)

type State128x2 struct {
	V0, V1, V2, V3, V4, V5, V6, V7 simd.Uint8x32
}

func InitState128x2(key simd.Uint8x16, nonce simd.Uint8x16) State128x2 {
	c0 := [2]uint64{0x000101020305080d, 0x1522375990e97962}
	c1 := [2]uint64{0xdb3d18556dc22ff1, 0x2011314273b528dd}
	C0 := simd.LoadUint64x2(&c0).AsUint8x16()
	C1 := simd.LoadUint64x2(&c1).AsUint8x16()

	S0 := key.Xor(nonce)
	S1 := C1
	S2 := C0
	S3 := C1
	S4 := key.Xor(nonce)
	S5 := key.Xor(C0)
	S6 := key.Xor(C1)
	S7 := key.Xor(C0)

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
		state = UpdateState128x2(state, Key, Nonce)
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
	// TODO(sjy): implement Finalize.
	panic("implement")
}

func AESx2(M0 simd.Uint8x32, M1 simd.Uint8x32) simd.Uint8x32 {
	// TODO: do this as a vector op.

	m00 := M0.GetLo()
	m10 := M1.GetLo()
	result0 := aesRoundGeneric(m00.AsUint64x2(), m10.AsUint64x2())

	m01 := M0.GetHi()
	m11 := M1.GetHi()
	result1 := aesRoundGeneric(m01.AsUint64x2(), m11.AsUint64x2())

	return simd.Uint8x32{}.SetLo(result0.AsUint8x16()).SetHi(result1.AsUint8x16())
}
