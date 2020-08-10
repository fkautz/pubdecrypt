package pubdecrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPKCS15Encrypt(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	secretMessage := "hello world"

	encryptedMessage, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, []byte(secretMessage))
	assert.NoError(t, err)
	decryptedMessage, _ := rsa.DecryptPKCS1v15(nil, privateKey, encryptedMessage)
	assert.NoError(t, err)

	assert.Equal(t, secretMessage, string(decryptedMessage))
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

	assert.Equal(t, secretMessage, string(decryptedMessage.Bytes()))
}

func TestLocalPKCS15Encrypt(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	secretMessage := "hello world"

	encryptedMessage, err := EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, []byte(secretMessage))
	assert.NoError(t, err)
	decryptedMessage, _ := DecryptPKCS1v15(nil, privateKey, encryptedMessage)
	assert.NoError(t, err)

	assert.Equal(t, secretMessage, string(decryptedMessage))
}
