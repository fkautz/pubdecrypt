package pubdecrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalPass(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	secretMessage := "hello world"
	fmt.Println("unencrypted message:", secretMessage)

	encryptedMessage, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, []byte(secretMessage), nil)
	assert.NoError(t, err)

	fmt.Println(hex.EncodeToString(encryptedMessage))

	message, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedMessage, nil)
	assert.NoError(t, err)

	log.Println("decrypt succeeded:", message)
	log.Println(message)
}

func TestReversePass(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	secretMessage := "hello world"

	fmt.Println("unencrypted message:", secretMessage)

	m := big.NewInt(0)

	m.SetBytes([]byte(secretMessage))

	e := big.NewInt(int64(privateKey.E))
	n := privateKey.N
	d := privateKey.D

	encryptedMessage := RsaEncrypt(m, e, n)
	decryptedMessage := RsaEncrypt(encryptedMessage, d, privateKey.PublicKey.N)

	fmt.Println(hex.EncodeToString(encryptedMessage.Bytes()))

	log.Println("original message:", m.Bytes())
	log.Println("encrypted message:", encryptedMessage.Bytes())
	log.Println("decrypted message:", string(decryptedMessage.Bytes()))
}
