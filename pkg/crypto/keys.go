package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

type RSAEncryptor struct {
	publicKey *rsa.PublicKey
}

type RSADecryptor struct {
	privateKey *rsa.PrivateKey
}

func NewRSAEncryptor(keyFile string) (*RSAEncryptor, error) {
	pubKey, err := loadPublicKey(keyFile)
	if err != nil {
		return nil, err
	}
	return &RSAEncryptor{publicKey: pubKey}, nil
}

func NewRSADecryptor(keyFile string) (*RSADecryptor, error) {
	privKey, err := loadPrivateKey(keyFile)
	if err != nil {
		return nil, err
	}
	return &RSADecryptor{privateKey: privKey}, nil
}

func loadPublicKey(filename string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %v", err)
	}

	// Try parsing as OpenSSH public key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(keyData)
	if err == nil {
		cryptoPublicKey := pubKey.(ssh.CryptoPublicKey).CryptoPublicKey()
		rsaKey, ok := cryptoPublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA public key")
		}
		return rsaKey, nil
	}

	// If OpenSSH parsing failed, try PEM format
	block, _ := pem.Decode(keyData)
	if block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA public key")
		}
		return rsaKey, nil
	}

	return nil, fmt.Errorf("failed to parse public key in any supported format")
}

func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading private key file: %v", err)
	}

	// Parse the private key
	parsedKey, err := ssh.ParseRawPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}

	// Assert that it's an RSA key
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}

	return rsaKey, nil
}

func (e *RSAEncryptor) EncryptKey(key []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, e.publicKey, key, nil)
}

func (d *RSADecryptor) DecryptKey(encryptedKey []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, d.privateKey, encryptedKey, nil)
}