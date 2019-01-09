package schnorr

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var Curve = secp256k1.S256()

// Sign a 32 byte message with the private key, returning a 64 byte signature.
// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#signing
func Sign(privateKey *big.Int, message []byte) ([]byte, error) {
	if len(message) != 32 {
		return nil, errors.New("The message must be a 32-byte array")
	}
	// not(1 <= seckey <= n-1)
	// if privateKey.Cmp() {
	// 	return nil, errors.New("The secret key must be an integer in the range 1..n-1.")
	// }
	d := intToByte(privateKey)
	k0, err := deterministicGetK0(d, message)
	if err != nil {
		return nil, err
	}

	Rx, Ry := Curve.ScalarBaseMult(intToByte(k0))
	k := getK(Ry, k0)
	Px, Py := Curve.ScalarBaseMult(d)
	rX := intToByte(Rx)
	e := getE(rX, Px, Py, message)
	e.Mul(e, privateKey)
	k.Add(k, e)
	k.Mod(k, Curve.N)
	return append(rX, intToByte(k)...), nil
}

// Verify a 64 byte signature of a 32 byte message against the public key.
// Returns an error if verification fails.
// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#verification
func Verify(pubKey, message, signature []byte) (bool, error) {
	if len(pubKey) != 33 {
		return false, errors.New("The public key must be a 33-byte array")
	}
	if len(message) != 32 {
		return false, errors.New("The message must be a 32-byte array")
	}
	if len(signature) != 64 {
		return false, errors.New("The signature must be a 64-byte array")
	}

	Px, Py := Unmarshal(Curve, pubKey)

	if Px == nil && Py == nil {
		return false, errors.New("signature verification failed")
	}
	r := new(big.Int).SetBytes(signature[:32])
	if r.Cmp(Curve.P) >= 0 {
		return false, errors.New("r is larger than or equal to field size")
	}
	s := new(big.Int).SetBytes(signature[32:64])
	if s.Cmp(Curve.N) >= 0 {
		return false, errors.New("s is larger than or equal to curve order")
	}

	e := getE(intToByte(r), Px, Py, message)
	sGx, sGy := Curve.ScalarBaseMult(intToByte(s))
	// e.Sub(Curve.N, e)
	ePx, ePy := Curve.ScalarMult(Px, Py, intToByte(e))
	ePy.Sub(Curve.P, ePy)
	Rx, Ry := Curve.Add(sGx, sGy, ePx, ePy)

	if (Rx == nil && Ry == nil) || big.Jacobi(Ry, Curve.P) != 1 || Rx.Cmp(r) != 0 {
		return false, errors.New("signature verification failed")
	}
	return true, nil
}

func getE(rX []byte, Px, Py *big.Int, m []byte) *big.Int {
	r := append(rX, Marshal(Curve, Px, Py)...)
	r = append(r, m...)
	h := sha256.Sum256(r)
	i := new(big.Int).SetBytes(h[:])
	return i.Mod(i, Curve.N)
}

func getK(Ry, k0 *big.Int) *big.Int {
	if big.Jacobi(Ry, Curve.P) == 1 {
		return k0
	}
	return k0.Sub(Curve.N, k0)
}

func deterministicGetK0(d, message []byte) (*big.Int, error) {
	h := sha256.Sum256(append(d[:], message...))
	i := new(big.Int).SetBytes(h[:])
	k0 := i.Mod(i, Curve.N)
	if k0.Sign() == 0 {
		return nil, errors.New("k0 is zero")
	}

	return k0, nil
}

// https://github.com/btcsuite/btcd/blob/master/btcec/pubkey.go#L187
func intToByte(i *big.Int) []byte {
	b1, b2 := [32]byte{}, i.Bytes()
	copy(b1[32-len(b2):], b2)
	return b1[:]
}

// https://go-review.googlesource.com/c/go/+/1883/2/src/crypto/elliptic/elliptic.go#364
func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3

	ret := make([]byte, 1+byteLen)
	ret[0] = 2 // compressed point

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	ret[0] += byte(y.Bit(0))
	return ret
}

// func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
// 	byteLen := (curve.Params().BitSize + 7) >> 3
// 	if (data[0] &^ 1) != 2 {
// 		return // unrecognized point encoding
// 	}

// 	if len(data) != 1+byteLen {
// 		return
// 	}

// 	// Based on Routine 2.2.4 in NIST Mathematical routines paper
// 	params := curve.Params()
// 	tx := new(big.Int).SetBytes(data[1 : 1+byteLen])
// 	// y² = x³ - 3x + b
// 	y2 := new(big.Int).Mul(tx, tx)
// 	y2.Mul(y2, tx)
// 	threeX := new(big.Int).Lsh(tx, 1)
// 	threeX.Add(threeX, tx)
// 	y2.Sub(y2, threeX)
// 	y2.Add(y2, params.B)
// 	y2.Mod(y2, params.P)

// 	ty := new(big.Int)
// 	if ty.ModSqrt(y2, params.P) == nil {
// 		return //  "y^2" is not a square: invalid point
// 	}

// 	var y2c big.Int
// 	y2c.Mul(ty, ty).Mod(&y2c, params.P)
// 	if y2c.Cmp(y2) != 0 {
// 		return // sqrt(y2)^2 != y2: invalid point
// 	}
// 	if ty.Bit(0) != uint(data[0]&1) {
// 		ty.Sub(params.P, ty)
// 	}

// 	x, y = tx, ty // valid point: return it
// 	return
// }

// Unmarshal converts a point, serialised by Marshal, into an x, y pair. On
// error, x = nil.
func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if (data[0] &^ 1) != 2 {
		return
	}
	if len(data) != 1+byteLen {
		return
	}

	odd := new(big.Int).SetInt64(int64(data[0]) - 2)
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	P := curve.Params().P
	ySq := new(big.Int)
	ySq.Exp(x, new(big.Int).SetInt64(3), P)
	ySq.Add(ySq, new(big.Int).SetInt64(7))
	ySq.Mod(ySq, P)
	y0 := new(big.Int)
	P1 := new(big.Int).Add(P, new(big.Int).SetInt64(1))
	d := new(big.Int).Mod(P1, new(big.Int).SetInt64(4))
	P1.Sub(P1, d)
	P1.Div(P1, new(big.Int).SetInt64(4))
	y0.Exp(ySq, P1, P)

	if new(big.Int).Exp(y0, new(big.Int).SetInt64(2), P).Cmp(ySq) != 0 {
		return nil, nil
	}
	if new(big.Int).And(y0, new(big.Int).SetInt64(1)).Cmp(odd) != 0 {
		y = y0.Sub(P, y0)
	} else {
		y = y0
	}
	return
}
