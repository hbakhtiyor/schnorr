package schnorr

import (
	"math/big"
	"strings"
	"testing"

	"encoding/hex"
)

func TestSign(t *testing.T) {
	for _, test := range testCases {
		if test.d == "" {
			continue
		}

		// given
		d, ok := new(big.Int).SetString(test.d, 16)
		if !ok {
			t.Fatalf("Unexpected error from new(big.Int).SetString(%s, 16)", test.d)
		}

		var m [32]byte

		message, err := hex.DecodeString(test.m)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", test.m, err)
		}
		copy(m[:], message)

		// when
		result, err := Sign(d, m)
		if err != nil {
			t.Fatalf("Unexpected error from Sign(%s, %s): %v", test.d, test.m, err)
		}

		observed := hex.EncodeToString(result[:])
		expected := strings.ToLower(test.sig)

		// then
		if observed != expected {
			t.Fatalf("Sign(%s, %s) = %s, want %s", test.d, test.m, observed, expected)
		}
	}
}

func TestAggregateSignatures(t *testing.T) {
	pks := []*big.Int{}
	var (
		m  [32]byte
		pk [33]byte
	)

	Pxs, Pys := []*big.Int{}, []*big.Int{}
	for i, test := range testCases {
		if test.d == "" {
			continue
		}

		privKey, ok := new(big.Int).SetString(test.d, 16)
		if !ok {
			t.Fatalf("Unexpected error from new(big.Int).SetString(%s, 16)", test.d)
		}
		pks = append(pks, privKey)

		if i == 0 {
			message, err := hex.DecodeString(test.m)
			if err != nil {
				t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", test.m, err)
			}
			copy(m[:], message)
		}

		Px, Py := Curve.ScalarBaseMult(privKey.Bytes())
		Pxs = append(Pxs, Px)
		Pys = append(Pys, Py)
	}

	t.Run("Can sign and verify two aggregated signatures over same message", func(t *testing.T) {
		t.Skip()
		sig, err := AggregateSignatures(pks[:2], m)
		if err != nil {
			t.Fatalf("Unexpected error from AggregateSignatures(%x, %x): %v", pks[:2], m, err)
		}

		Px, Py := Curve.Add(Pxs[0], Pys[0], Pxs[1], Pys[1])
		copy(pk[:], Marshal(Curve, Px, Py))

		observedSum := hex.EncodeToString(pk[:])
		expected := "02e23a31be992bc8194e55c5eada97e73b6a973016394a3a574cc053869df027c6"

		// then
		if observedSum != expected {
			t.Fatalf("Sum of public keys, %s, want %s", observedSum, expected)
		}

		observed, err := Verify(pk, m, sig)
		if err != nil {
			t.Fatalf("Unexpected error from Verify(%x, %x, %x): %v", pk, m, sig, err)
		}

		// then
		if !observed {
			t.Fatalf("Verify(%x, %x, %x) = %v, want %v", pk, m, sig, observed, true)
		}
	})

	t.Run("Can sign and verify two more aggregated signatures over same message", func(t *testing.T) {
		t.Skip()
		sig, err := AggregateSignatures(pks[1:3], m)
		if err != nil {
			t.Fatalf("Unexpected error from AggregateSignatures(%x, %x): %v", pks[1:3], m, err)
		}

		Px, Py := Curve.Add(Pxs[1], Pys[1], Pxs[2], Pys[2])
		copy(pk[:], Marshal(Curve, Px, Py))

		observedSum := hex.EncodeToString(pk[:])
		expected := "03fa896c006899f1d62f5560410a7116d9f87bb6724f3496f1b38e3403930c2419"

		// then
		if observedSum != expected {
			t.Fatalf("Sum of public keys, %s, want %s", observedSum, expected)
		}

		observed, err := Verify(pk, m, sig)
		if err != nil {
			t.Fatalf("Unexpected error from Verify(%x, %x, %x): %v", pk, m, sig, err)
		}

		// then
		if !observed {
			t.Fatalf("Verify(%x, %x, %x) = %v, want %v", pk, m, sig, observed, true)
		}
	})

	t.Run("Can sign and verify three aggregated signatures over same message", func(t *testing.T) {
		t.Skip()
		sig, err := AggregateSignatures(pks[:3], m)
		if err != nil {
			t.Fatalf("Unexpected error from AggregateSignatures(%x, %x): %v", pks[:3], m, err)
		}

		Px, Py := Curve.Add(Pxs[0], Pys[0], Pxs[1], Pys[1])
		Px, Py = Curve.Add(Px, Py, Pxs[2], Pys[2])
		copy(pk[:], Marshal(Curve, Px, Py))

		observedSum := hex.EncodeToString(pk[:])
		expected := "02313414b84f2f9dabca753c5d335c46960003a729c6c08814635bc75a16d93343"

		// then
		if observedSum != expected {
			t.Fatalf("Sum of public keys, %s, want %s", observedSum, expected)
		}

		observed, err := Verify(pk, m, sig)
		if err != nil {
			t.Fatalf("Unexpected error from Verify(%x, %x, %x): %v", pk, m, sig, err)
		}

		// then
		if !observed {
			t.Fatalf("Verify(%x, %x, %x) = %v, want %v", pk, m, sig, observed, true)
		}
	})

	t.Run("Can aggregate and verify example in README", func(t *testing.T) {
		privKey1 := "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
		privateKey1, ok := new(big.Int).SetString(privKey1, 16)
		if !ok {
			t.Fatalf("Unexpected error from new(big.Int).SetString(%s, 16)", privKey1)
		}

		privKey2 := "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7"
		privateKey2, ok := new(big.Int).SetString(privKey2, 16)
		if !ok {
			t.Fatalf("Unexpected error from new(big.Int).SetString(%s, 16)", privKey2)
		}

		msg := "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"

		message, err := hex.DecodeString(msg)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", msg, err)
		}
		copy(m[:], message)

		pks := []*big.Int{privateKey1, privateKey2}
		aggregatedSignature, err := AggregateSignatures(pks, m)
		expected := "d60d7f81c15d57b04f8f6074de17f1b9eef2e0a9c9b2e93550c15b45d6998dc24ef5e393b356e7c334f36cee15e0f5f1e9ce06e7911793ddb9bd922d545b7525"
		observed := hex.EncodeToString(aggregatedSignature[:])

		// then
		if observed != expected {
			t.Fatalf("AggregateSignatures(%x, %x) = %s, want %s", pks, message, observed, expected)
		}
		if err != nil {
			t.Fatalf("Unexpected error from AggregateSignatures(%x, %x): %v", pks, message, err)
		}

		// verifying an aggregated signature
		pubKey1 := "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
		pubKey2 := "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B"

		publicKey1, err := hex.DecodeString(pubKey1)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", pubKey1, err)
		}

		publicKey2, err := hex.DecodeString(pubKey2)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", pubKey2, err)
		}

		P1x, P1y := Unmarshal(Curve, publicKey1)
		P2x, P2y := Unmarshal(Curve, publicKey2)
		Px, Py := Curve.Add(P1x, P1y, P2x, P2y)

		copy(pk[:], Marshal(Curve, Px, Py))

		observed = hex.EncodeToString(pk[:])
		expected = "03f0a6305d39a34582ba49a78bdf38ced935b3efce1e889d6820103665f35ee45b"

		// then
		if observed != expected {
			t.Fatalf("Sum of public keys, %s, want %s", observed, expected)
		}

		result, err := Verify(pk, m, aggregatedSignature)
		if err != nil {
			t.Fatalf("Unexpected error from Verify(%x, %x, %x): %v", pk, m, aggregatedSignature, err)
		}

		// then
		if !result {
			t.Fatalf("Verify(%x, %x, %x) = %v, want %v", pk, m, aggregatedSignature, observed, true)
		}
	})
}

func TestVerify(t *testing.T) {
	for _, test := range testCases {
		// given
		var (
			pk  [33]byte
			m   [32]byte
			sig [64]byte
		)

		pubKey, err := hex.DecodeString(test.pk)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", test.pk, err)
		}
		copy(pk[:], pubKey)

		message, err := hex.DecodeString(test.m)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", test.m, err)
		}
		copy(m[:], message)

		signature, err := hex.DecodeString(test.sig)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", test.sig, err)
		}
		copy(sig[:], signature)

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Unexpected panic from Verify(%s, %s, %s): %v ", test.pk, test.m, test.sig, r)
			}
		}()

		// when
		observed, err := Verify(pk, m, sig)
		if err != nil && test.err == nil {
			t.Fatalf("Unexpected error from Verify(%s, %s, %s): %v", test.pk, test.m, test.sig, err)
		} else if err != nil && err.Error() != test.err.Error() {
			t.Fatalf("Unexpected error from Verify(%s, %s, %s): %v", test.pk, test.m, test.sig, err)
		}

		// then
		if observed != test.result {
			t.Fatalf("Verify(%s, %s, %s) = %v, want %v", test.pk, test.m, test.sig, observed, test.result)
		}
	}
}

func TestBatchVerify(t *testing.T) {
	publicKeys := [][33]byte{}
	messages := [][32]byte{}
	signatures := [][64]byte{}
	for _, test := range testCases {
		if !test.result {
			continue
		}

		// given
		var (
			pk  [33]byte
			m   [32]byte
			sig [64]byte
		)

		pubKey, err := hex.DecodeString(test.pk)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", test.pk, err)
		}
		copy(pk[:], pubKey)

		message, err := hex.DecodeString(test.m)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", test.m, err)
		}
		copy(m[:], message)

		signature, err := hex.DecodeString(test.sig)
		if err != nil {
			t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", test.sig, err)
		}
		copy(sig[:], signature)

		publicKeys = append(publicKeys, pk)
		messages = append(messages, m)
		signatures = append(signatures, sig)
	}

	// when
	observed, err := BatchVerify(publicKeys, messages, signatures)
	if err != nil {
		t.Fatalf("Unexpected error from BatchVerify(%x, %x, %x): %v", publicKeys, messages, signatures, err)
	}

	// then
	if !observed {
		t.Fatalf("BatchVerify(%x, %x, %x) = %v, want %v", publicKeys, messages, signatures, observed, true)
	}
}

func BenchmarkSign(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, test := range testCases {
			if test.d == "" {
				continue
			}
			var m [32]byte
			d, _ := new(big.Int).SetString(test.d, 16)
			message, _ := hex.DecodeString(test.m)
			copy(m[:], message)
			Sign(d, m)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, test := range testCases {
			var (
				pk  [33]byte
				m   [32]byte
				sig [64]byte
			)

			pubKey, _ := hex.DecodeString(test.pk)
			message, _ := hex.DecodeString(test.m)
			signature, _ := hex.DecodeString(test.sig)
			copy(pk[:], pubKey)
			copy(m[:], message)
			copy(sig[:], signature)

			Verify(pk, m, sig)
		}
	}
}
