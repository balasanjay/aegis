package aegis_test

import (
	"encoding/hex"
	"testing"
	"encoding/binary"
	"bytes"

	"github.com/balasanjay/aegis"
)

var aegis128x2TestCases = []struct {
		name string

		// Inputs (all hex-encoded)
		key            string
		nonce          string
		plaintext      string
		additionalData string

		// Expected outputs (all hex-encoded).
		expectedCiphertext string
		expectedTag16      string
		expectedTag32      string
	}{
		{
			name: "TestVector1",

			key:            "000102030405060708090a0b0c0d0e0f",
			nonce:          "101112131415161718191a1b1c1d1e1f",
			plaintext:      "",
			additionalData: "",

			expectedCiphertext: "",
			expectedTag16:      "63117dc57756e402819a82e13eca8379",
			expectedTag32: "b92c71fdbd358b8a4de70b27631ace90" +
				"cffd9b9cfba82028412bac41b4f53759",
		},

		{
			name: "TestVector2",

			key:   "000102030405060708090a0b0c0d0e0f",
			nonce: "101112131415161718191a1b1c1d1e1f",
			plaintext: "04050607040506070405060704050607" +
				"04050607040506070405060704050607" +
				"04050607040506070405060704050607" +
				"04050607040506070405060704050607" +
				"04050607040506070405060704050607" +
				"04050607040506070405060704050607" +
				"04050607040506070405060704050607" +
				"0405060704050607",
			additionalData: "0102030401020304",

			expectedCiphertext: "5795544301997f93621b278809d6331b" +
				"3bfa6f18e90db12c4aa35965b5e98c5f" +
				"c6fb4e54bcb6111842c20637252eff74" +
				"7cb3a8f85b37de80919a589fe0f24872" +
				"bc926360696739e05520647e390989e1" +
				"eb5fd42f99678a0276a498f8c454761c" +
				"9d6aacb647ad56be62b29c22cd4b5761" +
				"b38f43d5a5ee062f",
			expectedTag16: "1aebc200804f405cab637f2adebb6d77",
			expectedTag32: "c471876f9b4978c44f2ae1ce770cdb11" +
				"a094ee3feca64e7afcd48bfe52c60eca",
		},
	}


func TestAegis128x2(t *testing.T) {
	for _, tc := range aegis128x2TestCases {
		t.Run(tc.name, func(t *testing.T) {
			key := unhex(tc.key)
			nonce := unhex(tc.nonce)

			aead := aegis.NewAEAD128x2(([16]byte)(key))

			{

				ciphertext, tag := aead.DetachedSeal16(nil, nonce, unhex(tc.plaintext), unhex(tc.additionalData))

				gotCiphertext := hex.EncodeToString(ciphertext)
				if gotCiphertext != tc.expectedCiphertext {
					t.Errorf("got ciphertext=%q, want ciphertext=%q", gotCiphertext, tc.expectedCiphertext)
				}

				gotTag := hex.EncodeToString(tag[:])
				if gotTag != tc.expectedTag16 {
					t.Errorf("got tag=%q, want tag=%q", gotTag, tc.expectedTag16)
				}

				rtPlaintext, err := aead.DetachedOpen16(nil, nonce, ciphertext, unhex(tc.additionalData), tag)
				gotRtPlaintext := hex.EncodeToString(rtPlaintext)
				if err != nil {
					t.Errorf("got unexpected error: %v", err)
				}
				if gotRtPlaintext != tc.plaintext {
					t.Errorf("got roundtrip plaintext=%q, want plaintext=%q", gotRtPlaintext, tc.plaintext)
				}
			}

			{

				ciphertext, tag := aead.DetachedSeal32(nil, nonce, unhex(tc.plaintext), unhex(tc.additionalData))

				gotCiphertext := hex.EncodeToString(ciphertext)
				if gotCiphertext != tc.expectedCiphertext {
					t.Errorf("got ciphertext=%q, want ciphertext=%q", gotCiphertext, tc.expectedCiphertext)
				}

				gotTag := hex.EncodeToString(tag[:])
				if gotTag != tc.expectedTag32 {
					t.Errorf("got tag=%q, want tag=%q", gotTag, tc.expectedTag32)
				}

				rtPlaintext, err := aead.DetachedOpen32(nil, nonce, ciphertext, unhex(tc.additionalData), tag)
				gotRtPlaintext := hex.EncodeToString(rtPlaintext)
				if err != nil {
					t.Errorf("got unexpected error: %v", err)
				}
				if gotRtPlaintext != tc.plaintext {
					t.Errorf("got roundtrip plaintext=%q, want plaintext=%q", gotRtPlaintext, tc.plaintext)
				}
			}
		})
	}
}


func FuzzAegis128x2Roundtrip(f *testing.F) {
	for _, tc := range aegis128x2TestCases {
		key := ([16]byte)(unhex(tc.key))
		key0 := binary.LittleEndian.Uint64(key[0:8])
		key1 := binary.LittleEndian.Uint64(key[8:16])

		nonce := ([16]byte)(unhex(tc.nonce))
		nonce0 := binary.LittleEndian.Uint64(nonce[0:8])
		nonce1 := binary.LittleEndian.Uint64(nonce[8:16])

		plaintext := unhex(tc.plaintext)
		additionalData := unhex(tc.additionalData)

		f.Add(key0, key1, nonce0, nonce1, plaintext, additionalData)
	}

	ciphertext := []byte{}
	rtPlaintext := []byte{}

	f.Fuzz(func(t *testing.T, key0 uint64, key1 uint64, nonce0 uint64, nonce1 uint64, plaintext []byte, additionalData []byte) {
		ciphertext = ciphertext[:0]
		rtPlaintext = rtPlaintext[:0]

		var key [16]byte
		binary.LittleEndian.PutUint64(key[0:8], key0)
		binary.LittleEndian.PutUint64(key[8:16], key1)

		var nonce [16]byte
		binary.LittleEndian.PutUint64(nonce[0:8], nonce0)
		binary.LittleEndian.PutUint64(nonce[8:16], nonce1)

		aead := aegis.NewAEAD128x2(key)

		ciphertext = aead.Seal(ciphertext, nonce[:], plaintext, additionalData)

		var err error
		rtPlaintext, err = aead.Open(rtPlaintext, nonce[:], ciphertext, additionalData)
		if err != nil {
			t.Errorf("should have roundtripped successfully, but failed: %v", err)
			return
		}

		if bytes.Compare(plaintext, rtPlaintext) != 0 {
			t.Errorf("plaintext did not roundtrip successfully")
			return
		}
	})
}

func TestAegisMac128x2(t *testing.T) {
	tcs := []struct {
		name string

		// Inputs (all hex-encoded)
		key   string
		nonce string
		data  string

		// Expected outputs (all hex-encoded).
		expectedTag16 string
		expectedTag32 string
	}{
		{
			name: "TestVector1",

			key:   "10010000000000000000000000000000",
			nonce: "10000200000000000000000000000000",
			data: "000102030405060708090a0b0c0d0e0f" +
				"101112131415161718191a1b1c1d1e1f" +
				"202122",

			expectedTag16: "6873ee34e6b5c59143b6d35c5e4f2c6e",
			expectedTag32: "afcba3fc2d63c8d6c7f2d63f3ec8fbbb" +
				"af022e15ac120e78ffa7755abccd959c",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			key := unhex(tc.key)
			nonce := unhex(tc.nonce)

			mac := aegis.NewMac128x2(([16]byte)(key))

			{

				tag := mac.Sum16(nonce, unhex(tc.data))

				gotTag := hex.EncodeToString(tag[:])
				if gotTag != tc.expectedTag16 {
					t.Errorf("got tag16=%q, want tag=%q", gotTag, tc.expectedTag16)
				}
			}

			{
				tag := mac.Sum32(nonce, unhex(tc.data))

				gotTag := hex.EncodeToString(tag[:])
				if gotTag != tc.expectedTag32 {
					t.Errorf("got tag32=%q, want tag=%q", gotTag, tc.expectedTag32)
				}
			}
		})
	}
}

func unhex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}

	return b
}
