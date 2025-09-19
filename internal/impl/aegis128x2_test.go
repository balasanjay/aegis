package impl_test

import (
	"encoding/hex"
	"fmt"
	"simd"
	"strings"
	"testing"

	"github.com/balasanjay/aegis/internal/impl"
)

func TestAegis128x2(t *testing.T) {
	key := unhex("000102030405060708090a0b0c0d0e0f")
	nonce := unhex("101112131415161718191a1b1c1d1e1f")

	state := impl.InitState128x2(simd.LoadUint8x16Slice(key), simd.LoadUint8x16Slice(nonce))

	var output strings.Builder
	appendV := func(i int, V simd.Uint8x32) {
		fmt.Fprintf(&output, "V[%d,0]: %s\n", i, hexSIMD(V.GetLo()))
		fmt.Fprintf(&output, "V[%d,1]: %s\n\n", i, hexSIMD(V.GetHi()))
	}

	appendV(0, state.V0)
	appendV(1, state.V1)
	appendV(2, state.V2)
	appendV(3, state.V3)
	appendV(4, state.V4)
	appendV(5, state.V5)
	appendV(6, state.V6)
	appendV(7, state.V7)

	got := strings.Trim(output.String(), "\n")

	expected := strings.Trim(`
V[0,0]: a4fc1ad9a72942fb88bd2cabbba6509a
V[0,1]: 80a40e392fc71084209b6c3319bdc6cc

V[1,0]: 380f435cf801763b1f0c2a2f7212052d
V[1,1]: 73796607b59b1b650ee91c152af1f18a

V[2,0]: 6ee1de433ea877fa33bc0782abff2dcb
V[2,1]: b9fab2ab496e16d1facaffd5453cbf14

V[3,0]: 85f94b0d4263bfa86fdf45a603d8b6ac
V[3,1]: 90356c8cadbaa2c969001da02e3feca0

V[4,0]: 09bd69ad3730174bcd2ce9a27cd1357e
V[4,1]: e610b45125796a4fcf1708cef5c4f718

V[5,0]: fcdeb0cf0a87bf442fc82383ddb0f6d6
V[5,1]: 61ad32a4694d6f3cca313a2d3f4687aa

V[6,0]: 571c207988659e2cdfbdaae77f4f37e3
V[6,1]: 32e6094e217573bf91fb28c145a3efa8

V[7,0]: ca549badf8faa58222412478598651cf
V[7,1]: 3407279a54ce76d2e2e8a90ec5d108eb`, "\n")

	if got != expected {
		t.Errorf("got:\n%v\nexpected:\n%v", got, expected)
		t.Errorf("len(got)=%d, len(expected)=%d", len(got), len(expected))
	}

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
