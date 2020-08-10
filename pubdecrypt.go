// Code from pubdecrypt authors: Copyright (c) 2020 pubdecrypt authors
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//////

// Code from Golang: Copyright (c) 2009 The Go Authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

package pubdecrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"
	"sync"
)

// RsaEncrypt implements the RSA algorithm for encrypting/decrypting
func RsaEncrypt(m, e, n *big.Int) *big.Int {
	c := big.NewInt(0)
	c = c.Exp(m, e, n)
	return c
}

// DecryptPKCS1v15 decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5.
// If rand != nil, it uses RSA blinding to avoid timing side-channel attacks.
//
// Note that whether this function returns an error or not discloses secret
// information. If an attacker can cause this function to run repeatedly and
// learn whether each instance returned an error then they can decrypt and
// forge signatures as if they had the private key. See
// DecryptPKCS1v15SessionKey for a way of solving this problem.
//
// Originally from https://golang.org/src/crypto/rsa/pkcs1v15.go?s=2396:2485#L66
func DecryptPKCS1v15(rand io.Reader, priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	if err := checkPub(&priv.PublicKey); err != nil {
		return nil, err
	}
	valid, out, index, err := decryptPKCS1v15(rand, priv, ciphertext)
	if err != nil {
		return nil, err
	}
	if valid == 0 {
		return nil, rsa.ErrDecryption
	}
	return out[index:], nil
}

// Originally from https://github.com/golang/go/blob/release-branch.go1.15/src/crypto/rsa/rsa.go#L75-L79
var (
	errPublicModulus       = errors.New("crypto/rsa: missing public modulus")
	errPublicExponentSmall = errors.New("crypto/rsa: public exponent too small")
	errPublicExponentLarge = errors.New("crypto/rsa: public exponent too large")
)

// checkPub sanity checks the public key before we use it.
// We require pub.E to fit into a 32-bit integer so that we
// do not have different behavior depending on whether
// int is 32 or 64 bits. See also
// https://www.imperialviolet.org/2012/03/16/rsae.html.
//
// Originally from https://github.com/golang/go/blob/release-branch.go1.15/src/crypto/rsa/rsa.go#L81-L97
func checkPub(pub *rsa.PublicKey) error {
	if pub.N == nil {
		return errPublicModulus
	}
	if pub.E < 2 {
		return errPublicExponentSmall
	}
	if pub.E > 1<<31-1 {
		return errPublicExponentLarge
	}
	return nil
}

// decryptPKCS1v15 decrypts ciphertext using priv and blinds the operation if
// rand is not nil. It returns one or zero in valid that indicates whether the
// plaintext was correctly structured. In either case, the plaintext is
// returned in em so that it may be read independently of whether it was valid
// in order to maintain constant memory access patterns. If the plaintext was
// valid then index contains the index of the original message in em.
//
// Originally from https://github.com/golang/go/blob/release-branch.go1.14/src/crypto/rsa/pkcs1v15.go#L134-L176
func decryptPKCS1v15(rand io.Reader, priv *rsa.PrivateKey, ciphertext []byte) (valid int, em []byte, index int, err error) {
	k := priv.Size()
	if k < 11 {
		err = rsa.ErrDecryption
		return
	}

	c := new(big.Int).SetBytes(ciphertext)
	m, err := decrypt(rand, priv, c)
	if err != nil {
		return
	}

	em = leftPad(m.Bytes(), k)
	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 2)

	// The remainder of the plaintext must be a string of non-zero random
	// octets, followed by a 0, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the zero.
	//   index: the offset of the first zero byte.
	lookingForIndex := 1

	for i := 2; i < len(em); i++ {
		equals0 := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
	}

	// The PS padding must be at least 8 bytes long, and it starts two
	// bytes into em.
	validPS := subtle.ConstantTimeLessOrEq(2+8, index)

	valid = firstByteIsZero & secondByteIsTwo & (^lookingForIndex & 1) & validPS
	index = subtle.ConstantTimeSelect(valid, index+1, 0)
	return valid, em, index, nil
}

// decrypt performs an RSA decryption, resulting in a plaintext integer. If a
// random source is given, RSA blinding is used.
//
// Originally from https://github.com/golang/go/blob/ba9e10889976025ee1d027db6b1cad383ec56de8/src/crypto/rsa/rsa.go#L487-L567
func decrypt(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	// TODO(agl): can we get away with reusing blinds?
	if c.Cmp(priv.N) > 0 {
		err = rsa.ErrDecryption
		return
	}
	if priv.N.Sign() == 0 {
		return nil, rsa.ErrDecryption
	}

	var ir *big.Int
	if random != nil {
		maybeReadByte(random)

		// Blinding enabled. Blinding involves multiplying c by r^e.
		// Then the decryption operation performs (m^e * r^e)^d mod n
		// which equals mr mod n. The factor of r can then be removed
		// by multiplying by the multiplicative inverse of r.

		var r *big.Int
		ir = new(big.Int)
		for {
			r, err = rand.Int(random, priv.N)
			if err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			ok := ir.ModInverse(r, priv.N)
			if ok != nil {
				break
			}
		}
		bigE := big.NewInt(int64(priv.E))
		rpowe := new(big.Int).Exp(r, bigE, priv.N) // N != 0
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priv.N)
		c = cCopy
	}

	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}

	if ir != nil {
		// Unblind.
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	return
}

// MaybeReadByte reads a single byte from r with ~50% probability. This is used
// to ensure that callers do not depend on non-guaranteed behaviour, e.g.
// assuming that rsa.GenerateKey is deterministic w.r.t. a given random stream.
//
// This does not affect tests that pass a stream of fixed bytes as the random
// source (e.g. a zeroReader).
//
// Originally from https://github.com/golang/go/blob/ba9e10889976025ee1d027db6b1cad383ec56de8/src/crypto/internal/randutil/randutil.go#L14-L38
var (
	closedChanOnce sync.Once
	closedChan     chan struct{}
)

func maybeReadByte(r io.Reader) {
	closedChanOnce.Do(func() {
		closedChan = make(chan struct{})
		close(closedChan)
	})

	select {
	case <-closedChan:
		return
	case <-closedChan:
		var buf [1]byte
		r.Read(buf[:])
	}
}

// Originally from https://github.com/golang/go/blob/ba9e10889976025ee1d027db6b1cad383ec56de8/src/crypto/rsa/rsa.go#L38-L39
var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

// leftPad returns a new slice of length size. The contents of input are right
// aligned in the new slice.
//
// Originally from https://github.com/golang/go/blob/release-branch.go1.14/src/crypto/rsa/rsa.go#L637-L647
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}

// EncryptPKCS1v15 encrypts the given message with RSA and the padding
// scheme from PKCS#1 v1.5.  The message must be no longer than the
// length of the public modulus minus 11 bytes.
//
// The rand parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same
// ciphertext.
//
// WARNING: use of this function to encrypt plaintexts other than
// session keys is dangerous. Use RSA OAEP in new protocols.
//
// Originally from https://github.com/golang/go/blob/release-branch.go1.14/src/crypto/rsa/pkcs1v15.go#L29-L66
func EncryptPKCS1v15(rand io.Reader, pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	maybeReadByte(rand)

	if err := checkPub(pub); err != nil {
		return nil, err
	}
	k := pub.Size()
	if len(msg) > k-11 {
		return nil, rsa.ErrMessageTooLong
	}

	// EM = 0x00 || 0x02 || PS || 0x00 || M
	em := make([]byte, k)
	em[1] = 2
	ps, mm := em[2:len(em)-len(msg)-1], em[len(em)-len(msg):]
	err := nonZeroRandomBytes(ps, rand)
	if err != nil {
		return nil, err
	}
	em[len(em)-len(msg)-1] = 0
	copy(mm, msg)

	m := new(big.Int).SetBytes(em)
	c := encrypt(new(big.Int), pub, m)

	copyWithLeftPad(em, c.Bytes())
	return em, nil
}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
//
// Originally from https://github.com/golang/go/blob/release-branch.go1.14/src/crypto/rsa/pkcs1v15.go#L29-L66
func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	_, err = io.ReadFull(rand, s)
	if err != nil {
		return
	}

	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(rand, s[i:i+1])
			if err != nil {
				return
			}
			// In tests, the PRNG may return all zeros so we do
			// this to break the loop.
			s[i] ^= 0x42
		}
	}

	return
}

// Originally from https://github.com/golang/go/blob/release-branch.go1.14/src/crypto/rsa/rsa.go#L353-L357
func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

// copyWithLeftPad copies src to the end of dest, padding with zero bytes as
// needed.
//
// Originally from https://github.com/golang/go/blob/release-branch.go1.14/src/crypto/rsa/pkcs1v15.go#L320-L328
func copyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}
