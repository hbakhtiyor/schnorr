package schnorr

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

var (
	// Curve is a KoblitzCurve which implements secp256k1.
	Curve = btcec.S256()

	// Zero holds a big integer of 0
	Zero = new(big.Int)
	// One holds a big integer of 1
	One = new(big.Int).SetInt64(1)
	// Two holds a big integer of 2
	Two = new(big.Int).SetInt64(2)
	// Three holds a big integer of 3
	Three = new(big.Int).SetInt64(3)
	// Four holds a big integer of 4
	Four = new(big.Int).SetInt64(4)
	// Seven holds a big integer of 7
	Seven = new(big.Int).SetInt64(7)
	// N2 holds a big integer of N-2
	N2 = new(big.Int).Sub(Curve.N, Two)
)

// Sign a 32 byte message with the private key, returning a 64 byte signature.
// Calling with a nil aux will cause the function to use a deterministic nonce.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#signing
func Sign(privateKey *big.Int, message [32]byte, aux []byte) ([64]byte, error) {
	sig := [64]byte{}
	if privateKey.Cmp(One) < 0 || privateKey.Cmp(new(big.Int).Sub(Curve.N, One)) > 0 {
		return sig, errors.New("the private key must be an integer in the range 1..n-1")
	}

	// d0 = privateKey
	Px, Py := Curve.ScalarBaseMult(intToByte(privateKey))
	d := new(big.Int)

	if new(big.Int).And(Py, One).Cmp(Zero) == 0 {
		// Py is even
		d = d.Set(privateKey)
	} else {
		d = d.Sub(Curve.N, privateKey)
	}

	var k0 *big.Int
	if aux != nil {
		if len(aux) != 32 {
			return sig, fmt.Errorf("aux must be 32 bytes, not %d", len(aux))
		}

		t := new(big.Int).Xor(
			d,
			new(big.Int).SetBytes(taggedHash("BIP0340/aux", aux)),
		)

		bundle := bytes.Buffer{}
		bundle.Write(t.Bytes())
		bundle.Write(Px.Bytes())
		bundle.Write(message[:])

		k0 = new(big.Int).Mod(
			new(big.Int).SetBytes(taggedHash("BIP0340/nonce", bundle.Bytes())),
			Curve.N,
		)
	} else {
		k0 = deterministicGetK0(d.Bytes(), message)
	}
	if k0.Sign() == 0 {
		return sig, errors.New("k0 is zero")
	}

	Rx, Ry := Curve.ScalarBaseMult(intToByte(k0))
	k := getK(Ry, k0)

	rX := intToByte(Rx)
	e := getE(Px, Py, rX, message)
	e.Mul(e, d)
	k.Add(k, e)
	k.Mod(k, Curve.N)

	copy(sig[:32], rX)
	copy(sig[32:], intToByte(k))
	return sig, nil
}

// Verify a 64 byte signature of a 32 byte message against the public key.
// Returns an error if verification fails.
// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification
func Verify(publicKey [32]byte, message [32]byte, signature [64]byte) (bool, error) {
	Px, Py := Unmarshal(Curve, publicKey[:])

	if Px == nil || Py == nil || !Curve.IsOnCurve(Px, Py) {
		return false, errors.New("signature verification failed")
	}
	r := new(big.Int).SetBytes(signature[:32])
	if r.Cmp(Curve.P) >= 0 {
		return false, errors.New("r is larger than or equal to field size")
	}
	s := new(big.Int).SetBytes(signature[32:])
	if s.Cmp(Curve.N) >= 0 {
		return false, errors.New("s is larger than or equal to curve order")
	}

	e := getE(Px, Py, intToByte(r), message)
	sGx, sGy := Curve.ScalarBaseMult(intToByte(s))
	// e.Sub(Curve.N, e)
	ePx, ePy := Curve.ScalarMult(Px, Py, intToByte(e))
	ePy.Sub(Curve.P, ePy)
	Rx, Ry := Curve.Add(sGx, sGy, ePx, ePy)

	if (Rx.Sign() == 0 && Ry.Sign() == 0) ||
		new(big.Int).And(Ry, One).Cmp(One) == 0 /* Ry is not even */ ||
		Rx.Cmp(r) != 0 {
		return false, errors.New("signature verification failed")
	}
	return true, nil
}

func getE(Px, Py *big.Int, rX []byte, m [32]byte) *big.Int {
	bundle := bytes.Buffer{}
	bundle.Write(rX)
	bundle.Write(Px.Bytes())
	bundle.Write(m[:])
	return new(big.Int).Mod(
		new(big.Int).SetBytes(taggedHash("BIP0340/challenge", bundle.Bytes())),
		Curve.N,
	)
}

func getK(Ry, k0 *big.Int) *big.Int {
	if new(big.Int).And(Ry, One).Cmp(Zero) == 0 {
		// is even
		return k0
	} else {
		return new(big.Int).Sub(Curve.N, k0)
	}
}

func deterministicGetK0(d []byte, message [32]byte) *big.Int {
	h := sha256.Sum256(append(d, message[:]...))
	i := new(big.Int).SetBytes(h[:])
	return i.Mod(i, Curve.N)
}

func deterministicGetRandA() (*big.Int, error) {
	a, err := rand.Int(rand.Reader, N2)
	if err != nil {
		return nil, err
	}

	return a.Add(a, One), nil
}

func intToByte(i *big.Int) []byte {
	b1, b2 := [32]byte{}, i.Bytes()
	copy(b1[32-len(b2):], b2)
	return b1[:]
}

// Marshal just encodes x as bytes. Unnecessary.
func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
	return x.Bytes()
}

// Unmarshal converts a point, serialised by Marshal, into an x, y pair. On
// error, x = nil.
func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if len(data) != byteLen {
		return
	}

	P := curve.Params().P
	x = new(big.Int).SetBytes(data)
	if x.Cmp(P) == 1 {
		return
	}

	ySq := new(big.Int).Mod(
		new(big.Int).Add(
			new(big.Int).Exp(x, Three, P),
			Seven,
		),
		P,
	)
	y = new(big.Int).Exp(
		ySq,
		new(big.Int).Div(
			new(big.Int).Add(P, One),
			Four,
		),
		P,
	)

	if new(big.Int).Exp(y, Two, P).Cmp(ySq) != 0 {
		return
	}

	if new(big.Int).And(y, One).Cmp(Zero) != 0 {
		// is even
		y = y.Sub(P, y)
	}

	return
}

func taggedHash(tag string, msg []byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(msg)
	return h.Sum(nil)
}
