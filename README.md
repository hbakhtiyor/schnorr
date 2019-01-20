[![GoDoc](https://godoc.org/github.com/hbakhtiyor/schnorr?status.svg)](https://godoc.org/github.com/hbakhtiyor/schnorr) [![Build Status](https://travis-ci.com/hbakhtiyor/schnorr.svg?branch=master)](https://travis-ci.com/hbakhtiyor/schnorr) [![Go Report Card](https://goreportcard.com/badge/github.com/hbakhtiyor/schnorr)](https://goreportcard.com/report/github.com/hbakhtiyor/schnorr) [![License](https://badges.fyi/github/license/hbakhtiyor/schnorr)](https://github.com/hbakhtiyor/schnorr/blob/master/LICENSE) ![Latest tag](https://badges.fyi/github/latest-tag/hbakhtiyor/schnorr)

Go implementation of the Schnorr BIP
=================

This is a Go implementation of the standard 64-byte Schnorr signature
scheme over the elliptic curve *secp256k1*.

The code is based upon the
[initial proposal of Pieter Wuille](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki)
when it didn't have a BIP number assigned yet.

The current version passes all test vectors provided
[here](https://raw.githubusercontent.com/sipa/bips/bip-schnorr/bip-schnorr/test-vectors.csv).
**But the author does not give any guarantees that the algorithm is implemented
correctly for every edge case!**

## Table of Contents

* [Usage](#usage)
* [API](#api)
    * [Sign(privateKey *big.Int, message [32]byte) ([64]byte, error)](#signprivatekey-bigint-message-byte-byte-error)
        * [Arguments](#arguments)
        * [Returns](#returns)
        * [Examples](#examples)
    * [Verify(publicKey [33]byte, message [32]byte, signature [64]byte) (bool, error)](#verifypubkey-message-signature-byte-bool-error)
        * [Arguments](#arguments-1)
        * [Returns](#returns-1)
        * [Examples](#examples-1)
    * [BatchVerify(publicKeys [][33]byte, messages [][32]byte, signatures [][64]byte) (bool, error)](#verifypubkey-message-signature-byte-bool-error)
        * [Arguments](#arguments-2)
        * [Returns](#returns-2)
        * [Examples](#examples-2)
    * [AggregateSignatures(privateKeys []*big.Int, message [32]byte) ([64]byte, error)](#verifypubkey-message-signature-byte-bool-error)
        * [Arguments](#arguments-3)
        * [Returns](#returns-3)
        * [Examples](#examples-3)
* [Benchmark](#benchmark)
   * [Hardware used](#hardware-used)
   * [Version](#version)
* [Credit](#credit)


## Usage
Install using:

```shell
go get -u github.com/hbakhtiyor/schnorr
```

In your code:

```go
import "github.com/hbakhtiyor/schnorr"

signature, err := schnorr.Sign(privateKey, message)

result, err := schnorr.Verify(publicKey, message, signature)

result, err := schnorr.BatchVerify(publicKeys, messages, signatures)

signature, err := schnorr.AggregateSignatures(privateKeys, message)
```
## API

Requiring the module gives an object with four methods:

### Sign(privateKey *big.Int, message [32]byte) ([64]byte, error)

Sign a 32-byte message with the private key, returning a 64-byte signature. Read [more](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#signing)

##### Arguments

1. privateKey (*big.Int): The integer secret key in the range 1..n-1.
2. message ([32]byte): The 32-byte array message.
  
##### Returns

([64]byte, error): A 64-byte array signature. An error if signing fails.

##### Examples

```go
var message [32]byte

privateKey, _ := new(big.Int).SetString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", 16)
msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
copy(message[:], msg)

signature, err := schnorr.Sign(privateKey, message)
if err != nil {
  fmt.Printf("The signing is failed: %v\n", err)
}
fmt.Printf("The signature is: %x\n", signature)
```

### Verify(publicKey [33]byte, message [32]byte, signature [64]byte) (bool, error)

Verify a 64-byte signature of a 32-byte message against the public key. Read [more](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#verification)

##### Arguments

1. publicKey ([33]byte): The 33-byte array public key.
2. message ([32]byte): The 32-byte array message.
3. signature ([64]byte): The 64-byte array signature.

##### Returns

(bool, error): True if signature is valid, An error if verification fails.

##### Examples

```go
var (
  publicKey [33]byte
  message   [32]byte
  signature [64]byte
)

pk, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
copy(publicKey[:], pk)
msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
copy(message[:], msg)
sig, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
copy(signature[:], sig)

if result, err := schnorr.Verify(publicKey, message, signature); err != nil {
  fmt.Printf("The signature verification failed: %v\n", err)
} else if result {
  fmt.Println("The signature is valid.")
}
```

### BatchVerify(publicKeys [][33]byte, messages [][32]byte, signatures [][64]byte) (bool, error)

Verify a list of 64-byte signatures of a 32-byte messages against the public keys. Read [more](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#batch-verification)

##### Arguments

1. publicKeys ([][33]byte): The list of 33-byte array public keys.
2. messages ([][32]byte): The list of 32-byte array messages.
3. signatures ([][64]byte): The list of 64-byte array signatures.

##### Returns

(bool, error): True if all signatures are valid, An error if one verification fails.

##### Examples

```go
var (
  publicKey  [33]byte
  message    [32]byte
  signature  [64]byte
  publicKeys [][33]byte
  messages   [][32]byte
  signatures [][64]byte
)

pk, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
copy(publicKey[:], pk)
publicKeys = append(publicKeys, publicKey)
pk, _ = hex.DecodeString("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
copy(publicKey[:], pk)
publicKeys = append(publicKeys, publicKey)
pk, _ = hex.DecodeString("026D7F1D87AB3BBC8BC01F95D9AECE1E659D6E33C880F8EFA65FACF83E698BBBF7")
copy(publicKey[:], pk)
publicKeys = append(publicKeys, publicKey)
msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
copy(message[:], msg)
messages = append(messages, message)
msg, _ = hex.DecodeString("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
copy(message[:], msg)
messages = append(messages, message)
msg, _ = hex.DecodeString("B2F0CD8ECB23C1710903F872C31B0FD37E15224AF457722A87C5E0C7F50FFFB3")
copy(message[:], msg)
messages = append(messages, message)
sig, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
copy(signature[:], sig)
signatures = append(signatures, signature)
sig, _ = hex.DecodeString("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380")
copy(signature[:], sig)
signatures = append(signatures, signature)
sig, _ = hex.DecodeString("68CA1CC46F291A385E7C255562068357F964532300BEADFFB72DD93668C0C1CAC8D26132EB3200B86D66DE9C661A464C6B2293BB9A9F5B966E53CA736C7E504F")
copy(signature[:], sig)
signatures = append(signatures, signature)

if result, err := schnorr.BatchVerify(publicKeys, messages, signatures); err != nil {
  fmt.Printf("The signature verification failed: %v\n", err)
} else if result {
  fmt.Println("The signature is valid.")
}
```

### AggregateSignatures(privateKeys []*big.Int, message [32]byte) ([64]byte, error)

Aggregate multiple signatures of different private keys over the same message into a single 64-byte signature.

##### Arguments

1. privateKeys ([]*big.Int): The list of integer secret keys in the range 1..n-1.
2. message ([32]byte): The list of 32-byte array messages.

##### Returns

(bool, error): True if all signatures are valid, An error if one verification fails.
([64]byte, error): A 64-byte array signature. An error if signing fails.

##### Examples

```go
var (
  publicKey [33]byte
  message   [32]byte
)

privateKey1, _ := new(big.Int).SetString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", 16)
privateKey2, _ := new(big.Int).SetString("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7", 16)
msg, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
copy(message[:], msg)

privateKeys := []*big.Int{privateKey1, privateKey2}
signature, _ := schnorr.AggregateSignatures(privateKeys, message)

// verifying an aggregated signature
pk, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
copy(publicKey[:], pk)
P1x, P1y := schnorr.Unmarshal(Curve, publicKey[:])

pk, _ = hex.DecodeString("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B")
copy(publicKey[:], pk)
P2x, P2y := schnorr.Unmarshal(Curve, publicKey[:])
Px, Py := Curve.Add(P1x, P1y, P2x, P2y)

copy(publicKey[:], schnorr.Marshal(Curve, Px, Py))

if result, err := schnorr.Verify(publicKey, message, signature); err != nil {
  fmt.Printf("The signature verification failed: %v\n", err)
} else if result {
  fmt.Println("The signature is valid.")
}
```

## Benchmarks

```
BenchmarkSign-4                  	    2000	   1015337 ns/op	   45812 B/op	     814 allocs/op
BenchmarkVerify-4                	     200	   8555659 ns/op	  217884 B/op	    3622 allocs/op
BenchmarkBatchVerify-4           	     100	  12114966 ns/op	  148343 B/op	    2220 allocs/op
BenchmarkAggregateSignatures-4   	    2000	    593665 ns/op	   21981 B/op	     400 allocs/op
```

##### Hardware used

* Intel® Core™ i3-2310M CPU @ 2.10GHz × 4
* 4Gb RAM

##### Versions

* Go 1.11.2
* Ubuntu 18.04.01 LTS x86_64 OS
* 4.15.0-39-generic kernel

## Credits

* https://github.com/guggero/bip-schnorr
* https://github.com/sipa/bips/tree/bip-schnorr/bip-schnorr
