package crypto

// Encryptor is an interface for encrypting keys
type Encryptor interface {
	EncryptKey(key []byte) ([]byte, error)
}

// Decryptor is an interface for decrypting keys
type Decryptor interface {
	DecryptKey(encryptedKey []byte) ([]byte, error)
}