package aegis_test

import (
	"encoding/hex"
	"testing"

	"github.com/balasanjay/aegis"
)

func TestAegis128x2(t *testing.T) {
	key := unhex("000102030405060708090a0b0c0d0e0f")
	nonce := unhex("101112131415161718191a1b1c1d1e1f")

	aead := aegis.NewAEAD128x2(([16]byte)(key))

	ciphertext, tag := aead.DetachedSeal16(nil, nonce, nil, nil)

	gotCiphertext := hex.EncodeToString(ciphertext)
	expectedCiphertext := ""
	if gotCiphertext != expectedCiphertext {
		t.Errorf("got ciphertext=%q, want ciphertext=%q", gotCiphertext, expectedCiphertext)
	}

	gotTag := hex.EncodeToString(tag[:])
	expectedTag := "63117dc57756e402819a82e13eca8379"
	if gotTag != expectedTag {
		t.Errorf("got tag=%q, want tag=%q", gotTag, expectedTag)
	}
}

func unhex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}

	return b
}
