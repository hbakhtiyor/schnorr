[![GoDoc](https://godoc.org/github.com/hbakhtiyor/schnorr?status.svg)](https://godoc.org/github.com/hbakhtiyor/schnorr) [![Build Status](https://travis-ci.com/hbakhtiyor/schnorr.svg?branch=master)](https://travis-ci.com/hbakhtiyor/schnorr) [![Go Report Card](https://goreportcard.com/badge/github.com/hbakhtiyor/schnorr)](https://goreportcard.com/report/github.com/hbakhtiyor/schnorr)![License](https://badges.fyi/github/license/hbakhtiyor/schnorr)![Latest tag](https://badges.fyi/github/latest-tag/hbakhtiyor/schnorr)

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
    * [Sign(privateKey *big.Int, message []byte) ([]byte, error)](#signprivatekey-bigint-message-byte-byte-error)
        * [Arguments](#arguments)
        * [Returns](#returns)
        * [Examples](#examples)
    * [Verify(pubKey, message, signature []byte) (bool, error)](#verifypubkey-message-signature-byte-bool-error)
        * [Arguments](#arguments-1)
        * [Returns](#returns-1)
        * [Examples](#examples-1)
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

result, err := schnorr.Verify(pubKey, message, signature)
```
## API

Requiring the module gives an object with two methods:

### Sign(privateKey *big.Int, message []byte) ([]byte, error)

Sign a 32 byte message with the private key, returning a 64 byte signature. Read [more](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#signing)

##### Arguments

1. privateKey (*big.Int): The secret key is an integer in the range 1..n-1.
2. message ([]byte): The message is a 32-byte array.
  
##### Returns

([]byte, error): A 64 byte array signature. An error if signing fails.

##### Examples

```go
// signing
privateKey, _ := new(big.Int).SetString("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", 16)
message, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
createdSignature, err := schnorr.Sign(privateKey, message)
if err != nil {
  fmt.Printf("The signing is failed: %v\n", err)
}
fmt.Printf("The signature is: %x\n", createdSignature)
```

### Verify(pubKey, message, signature []byte) (bool, error)

Verify a 64 byte signature of a 32 byte message against the public key. Read [more](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#verification)

##### Arguments

1. pubKey ([]byte): The public key is a 33-byte array.
2. message ([]byte): The message is a 32-byte array.
3. signature ([]byte): The signature is a 64-byte array.

##### Returns
(bool, error): True if signature is valid, An error if verification fails.

##### Examples
```go
// verifying
publicKey, _ := hex.DecodeString("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
message, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
signatureToVerify, _ := hex.DecodeString("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD")
if result, err := schnorr.Verify(publicKey, message, signatureToVerify); err != nil {
  fmt.Printf("The signature verification failed: %v\n", err)
} else if result {
  fmt.Println("The signature is valid.")
}
```

## Benchmarks

```
BenchmarkSign-4     	    1000	   1960591 ns/op	   34080 B/op	     602 allocs/op
BenchmarkVerify-4   	     100	  10368368 ns/op	  236963 B/op	    3605 allocs/op
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
