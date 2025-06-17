package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"file-encryptor/pkg/logging"
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

func GenerateRSAKeyPair(baseFileName string, logger *logging.Logger) error {
	privateKeyName, publicKeyName, err := GenerateRSAKeyPairWithNames(baseFileName, logger)
	if err != nil {
		return err
	}
	logger.LogInfof("Private Key: %s", privateKeyName)
	logger.LogInfof("Public Key: %s", publicKeyName)
	return nil
}

func GenerateRSAKeyPairWithNames(baseFileName string, logger *logging.Logger) (string, string, error) {
	logger.LogDebug("Generating RSA key pair")
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	publicKey := &privateKey.PublicKey
	logger.LogDebug("RSA key pair generated successfully")
	timestamp := time.Now().Format("20060102150405")
	privateKeyName := fmt.Sprintf("%s_private_%s.key", baseFileName, timestamp)
	publicKeyName := fmt.Sprintf("%s_public_%s.pub", baseFileName, timestamp)
	// Save private key in OpenSSH format
	if err := savePrivateKeyOpenSSH(privateKey, privateKeyName, logger); err != nil {
		return "", "", fmt.Errorf("failed to save private key (OpenSSH): %w", err)
	}

	// Save public key in OpenSSH format
	if err := savePublicKeyOpenSSH(publicKey, publicKeyName, logger); err != nil {
		return "", "", fmt.Errorf("failed to save public key (OpenSSH): %w", err)
	}
	return privateKeyName, publicKeyName, nil
}

func savePrivateKeyOpenSSH(privateKey *rsa.PrivateKey, filename string, logger *logging.Logger) error {
	logger.LogDebug("Saving private key in OpenSSH format")

	// Convert the private key to OpenSSH format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	// Create PEM block
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// Encode to PEM format
	pemBytes := pem.EncodeToMemory(pemBlock)
	if pemBytes == nil {
		return fmt.Errorf("failed to encode private key to PEM format")
	}

	// Write the private key with restricted permissions
	err := os.WriteFile(filename, pemBytes, 0600)
	if err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}

	logger.LogDebugf("Private key saved to: %s", filename)
	return nil
}

func savePublicKeyOpenSSH(publicKey *rsa.PublicKey, filename string, logger *logging.Logger) error {
	logger.LogDebug("Saving public key in OpenSSH format")
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to create ssh public key: %w", err)
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key to OpenSSH format: %w", err)
	}

	err = os.WriteFile(filename, pubKeyBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}
	logger.LogDebugf("Public key in OpenSSH format saved to: %s", filename)
	return nil
}
