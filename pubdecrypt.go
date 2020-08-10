package pubdecrypt

import "math/big"

// RsaEncrypt implements the RSA algorithm for encrypting/decrypting
func RsaEncrypt(m, e, n *big.Int) *big.Int {
	c := big.NewInt(0)
	c = c.Exp(m, e, n)
	return c
}
