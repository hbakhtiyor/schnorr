package schnorr

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSchnorr(t *testing.T) {
	for _, test := range testCases {
		if test.d == "" {
			continue
		}

		m, err := hex.DecodeString(test.m)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", test.m, err)
		}
		d, err := hex.DecodeString(test.d)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", test.d, err)
		}

		privateKey := curve.Scalar().SetBytes(d)
		publicKey := curve.Point().Mul(privateKey, curve.Point().Base())

		message := string(m)

		signature := *Sign(message, privateKey)
		fmt.Println(signature.String())
		derivedPublicKey := PublicKey(message, signature)
		if !derivedPublicKey.Equal(publicKey) {
			t.Errorf("Derived public key is incorrect.")
		}
		if !Verify(message, signature, publicKey) {
			t.Errorf("Signature verification is incorrect. Signature does not yield correct public key.")
		}

		fakePublicKey := curve.Point().Mul(curve.Scalar().Neg(curve.Scalar().One()), publicKey)
		if Verify(message, signature, fakePublicKey) {
			t.Errorf("Signature verification is incorrect. Signature claims to belong to an incorrect public key.")
		}
	}
}
