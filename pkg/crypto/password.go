package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize    = 16
	iterations  = 10000
	keySize     = 32
	hmacSize    = 32
)

type PasswordEncryptor struct {
	password string
}

type PasswordDecryptor struct {
	password string
}

func NewPasswordEncryptor(password string) (*PasswordEncryptor, error) {
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters long")
	}
	return &PasswordEncryptor{password: password}, nil
}

func NewPasswordDecryptor(password string) (*PasswordDecryptor, error) {
	if len(password) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters long")
	}
	return &PasswordDecryptor{password: password}, nil
}

func (e *PasswordEncryptor) EncryptKey(key []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("error generating salt: %v", err)
	}

	derivedKey := pbkdf2.Key([]byte(e.password), salt, iterations, keySize*2, sha256.New)
	encryptionKey := derivedKey[:keySize]
	hmacKey := derivedKey[keySize:]

	log.Printf("Generated derived key (length: %d)", len(derivedKey))

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %v", err)
	}

	ciphertext := make([]byte, len(key))
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("error generating IV: %v", err)
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, key)

	h := hmac.New(sha256.New, hmacKey)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	result := append(append(append(salt, iv...), ciphertext...), mac...)
	log.Printf("Encrypted key length: %d", len(result))
	return result, nil
}

func (d *PasswordDecryptor) DecryptKey(encryptedKey []byte) ([]byte, error) {
	if len(encryptedKey) < saltSize+aes.BlockSize+hmacSize {
		return nil, fmt.Errorf("encrypted key is too short (length: %d)", len(encryptedKey))
	}

	salt := encryptedKey[:saltSize]
	iv := encryptedKey[saltSize : saltSize+aes.BlockSize]
	ciphertext := encryptedKey[saltSize+aes.BlockSize : len(encryptedKey)-hmacSize]
	mac := encryptedKey[len(encryptedKey)-hmacSize:]

	derivedKey := pbkdf2.Key([]byte(d.password), salt, iterations, keySize*2, sha256.New)
	encryptionKey := derivedKey[:keySize]
	hmacKey := derivedKey[keySize:]

	log.Printf("Generated derived key (length: %d)", len(derivedKey))

	h := hmac.New(sha256.New, hmacKey)
	h.Write(ciphertext)
	expectedMAC := h.Sum(nil)

	if !hmac.Equal(mac, expectedMAC) {
		return nil, fmt.Errorf("decryption failed: incorrect password")
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %v", err)
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	log.Printf("Decrypted key length: %d", len(plaintext))

	return plaintext, nil
}