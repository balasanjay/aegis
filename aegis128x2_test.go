package aegis_test

import (
	_ "github.com/balasanjay/aegis"
	"github.com/balasanjay/aegis/internal/impl"
	"testing"
	"encoding/hex"
	"simd"
)

func TestAegis128x2(t *testing.T) {
	key := unhex("000102030405060708090a0b0c0d0e0f")
	nonce := unhex("101112131415161718191a1b1c1d1e1f")

	state := impl.InitState128x2(simd.LoadUint8x16Slice(key), simd.LoadUint8x16Slice(nonce))

	t.Logf("V0.L = %s", hexSIMD(state.V0.GetLo()))
	t.Logf("V0.H = %s", hexSIMD(state.V0.GetHi()))

	t.Logf("V1.L = %s", hexSIMD(state.V1.GetLo()))
	t.Logf("V1.H = %s", hexSIMD(state.V1.GetHi()))

	t.Logf("V2.L = %s", hexSIMD(state.V2.GetLo()))
	t.Logf("V2.H = %s", hexSIMD(state.V2.GetHi()))

	t.Logf("V3.L = %s", hexSIMD(state.V3.GetLo()))
	t.Logf("V3.H = %s", hexSIMD(state.V3.GetHi()))

	t.Logf("V4.L = %s", hexSIMD(state.V4.GetLo()))
	t.Logf("V4.H = %s", hexSIMD(state.V4.GetHi()))

	t.Logf("V5.L = %s", hexSIMD(state.V5.GetLo()))
	t.Logf("V5.H = %s", hexSIMD(state.V5.GetHi()))

	t.Logf("V6.L = %s", hexSIMD(state.V6.GetLo()))
	t.Logf("V6.H = %s", hexSIMD(state.V6.GetHi()))

	t.Logf("V7.L = %s", hexSIMD(state.V7.GetLo()))
	t.Logf("V7.H = %s", hexSIMD(state.V7.GetHi()))
}

func unhexSIMD(h string) simd.Uint8x16 {
	return simd.LoadUint8x16Slice(unhex(h))
}

func unhex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}

	return b
}

func hexSIMD(a simd.Uint8x16) string {
	var b [16]byte
	a.StoreSlice(b[:])
	return hex.EncodeToString(b[:])
}
