[![GoDoc](https://godoc.org/github.com/fiatjaf/schnorr?status.svg)](https://godoc.org/github.com/fiatjaf/schnorr) [![Build Status](https://travis-ci.com/fiatjaf/schnorr.svg?branch=master)](https://travis-ci.com/fiatjaf/schnorr) [![Go Report Card](https://goreportcard.com/badge/github.com/fiatjaf/schnorr)](https://goreportcard.com/report/github.com/fiatjaf/schnorr) [![License](https://badges.fyi/github/license/fiatjaf/schnorr)](https://github.com/fiatjaf/schnorr/blob/master/LICENSE) [![Latest tag](https://badges.fyi/github/latest-tag/fiatjaf/schnorr)](https://github.com/fiatjaf/schnorr/releases)

schnorr
=======

This is a simple and naïve Go implementation of the standard 64-byte Schnorr signature scheme over the elliptic curve *secp256k1* defined by [BIP340](https://bips.xyz/340). It only implements simple signing and verifying.

The current version passes all test vectors provided [with the BIP](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv) (but the author does not give any guarantees that the algorithm is implemented correctly for every edge case).

## Table of Contents

* [Usage](#usage)
* [API](#api)
    * [Sign(privateKey *big.Int, message [32]byte) ([64]byte, error)](#signprivatekey-bigint-message-32byte-64byte-error)
        * [Arguments](#arguments)
        * [Returns](#returns)
        * [Examples](#examples)
    * [Verify(publicKey [32]byte, message [32]byte, signature [64]byte) (bool, error)](#verifypublickey-32byte-message-32byte-signature-64byte-bool-error)
        * [Arguments](#arguments-1)
        * [Returns](#returns-1)
        * [Examples](#examples-1)
* [Credit](#credit)


## Usage
Install using:

```shell
go get -u github.com/fiatjaf/schnorr
```

In your code:

```go
import "github.com/fiatjaf/schnorr"

signature, err := schnorr.Sign(privateKey, message)
result, err := schnorr.Verify(publicKey, message, signature)
```
## API

Requiring the module gives an object with 2 methods:

### Sign(privateKey *big.Int, message [32]byte) ([64]byte, error)

Sign a 32-byte message with the private key, returning a 64-byte signature. Read [more](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#Default_Signing)

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

### Verify(publicKey [32]byte, message [32]byte, signature [64]byte) (bool, error)

Verify a 64-byte signature of a 32-byte message against the public key. Read [more](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#Verification).

##### Arguments

1. publicKey ([32]byte): The 32-byte array public key.
2. message ([32]byte): The 32-byte array message.
3. signature ([64]byte): The 64-byte array signature.

##### Returns

(bool, error): True if signature is valid, An error if verification fails.

##### Examples

```go
var (
  publicKey [32]byte
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

## Credits

* https://github.com/guggero/bip-schnorr
* https://github.com/hbakhtiyor/schnorr
* https://bips.xyz/340
