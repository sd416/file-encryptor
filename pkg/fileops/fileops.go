package fileops

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"file-encryptor/pkg/crypto"
	"file-encryptor/pkg/logging"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

const chunkSize = 64 * 1024 // 64KB chunks

func EncryptFile(inputFile, outputFile string, encryptor crypto.Encryptor, logger *logging.Logger) error {
	logger.Log(fmt.Sprintf("Starting encryption of file: %s", inputFile))
	startTime := time.Now()

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	bufReader := bufio.NewReaderSize(inFile, chunkSize)
	bufWriter := bufio.NewWriterSize(outFile, chunkSize)
	defer bufWriter.Flush()

	aesKey := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return fmt.Errorf("error generating AES key: %v", err)
	}
	logger.Log("Generated AES key")

	encryptedAESKey, err := encryptor.EncryptKey(aesKey)
	if err != nil {
		return fmt.Errorf("error encrypting AES key: %v", err)
	}
	logger.Log(fmt.Sprintf("Encrypted AES key (length: %d bytes)", len(encryptedAESKey)))

	if err := binary.Write(bufWriter, binary.BigEndian, uint32(len(encryptedAESKey))); err != nil {
		return fmt.Errorf("error writing key length: %v", err)
	}

	if _, err := bufWriter.Write(encryptedAESKey); err != nil {
		return fmt.Errorf("error writing encrypted key: %v", err)
	}
	logger.Log("Wrote encrypted AES key to file")

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("error creating AES cipher: %v", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("error generating IV: %v", err)
	}

	if _, err := bufWriter.Write(iv); err != nil {
		return fmt.Errorf("error writing IV: %v", err)
	}
	logger.Log("Wrote IV to file")

	numWorkers := runtime.NumCPU()
	jobs := make(chan []byte, numWorkers)
	results := make(chan []byte, numWorkers)
	errors := make(chan error, 1)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerIV []byte) {
			defer wg.Done()
			stream := cipher.NewCTR(block, workerIV)
			for chunk := range jobs {
				encryptedChunk := make([]byte, len(chunk))
				stream.XORKeyStream(encryptedChunk, chunk)
				results <- encryptedChunk
			}
		}(incrementIV(iv))
	}

	go func() {
		defer close(jobs)
		for {
			chunk := make([]byte, chunkSize)
			n, err := bufReader.Read(chunk)
			if err != nil {
				if err != io.EOF {
					errors <- fmt.Errorf("error reading input file: %v", err)
				}
				break
			}
			if n == 0 {
				break
			}
			jobs <- chunk[:n]
		}
	}()

	go func() {
		defer close(results)
		for encryptedChunk := range results {
			if _, err := bufWriter.Write(encryptedChunk); err != nil {
				errors <- fmt.Errorf("error writing encrypted data: %v", err)
				return
			}
		}
	}()

	wg.Wait()

	select {
	case err := <-errors:
		return err
	default:
	}

	duration := time.Since(startTime)
	logger.Log(fmt.Sprintf("Encryption completed. Duration: %v", duration))
	return nil
}

func DecryptFile(inputFile, outputFile string, decryptor crypto.Decryptor, logger *logging.Logger) error {
	logger.Log(fmt.Sprintf("Starting decryption of file: %s", inputFile))
	startTime := time.Now()

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("error opening input file: %v", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer outFile.Close()

	bufReader := bufio.NewReaderSize(inFile, chunkSize)
	bufWriter := bufio.NewWriterSize(outFile, chunkSize)
	defer bufWriter.Flush()

	var keyLength uint32
	if err := binary.Read(bufReader, binary.BigEndian, &keyLength); err != nil {
		return fmt.Errorf("error reading key length: %v", err)
	}
	logger.Log(fmt.Sprintf("Read encrypted AES key length: %d bytes", keyLength))

	encryptedAESKey := make([]byte, keyLength)
	if _, err := io.ReadFull(bufReader, encryptedAESKey); err != nil {
		return fmt.Errorf("error reading encrypted key: %v", err)
	}
	logger.Log(fmt.Sprintf("Read encrypted AES key (%d bytes)", len(encryptedAESKey)))

	aesKey, err := decryptor.DecryptKey(encryptedAESKey)
	if err != nil {
		return fmt.Errorf("error decrypting AES key: %v", err)
	}
	if len(aesKey) != 32 {
		return fmt.Errorf("decrypted AES key has incorrect length: %d (expected 32)", len(aesKey))
	}
	logger.Log("Successfully decrypted AES key")

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("error creating AES cipher: %v", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(bufReader, iv); err != nil {
		return fmt.Errorf("error reading IV: %v", err)
	}
	logger.Log("Read IV from file")

	numWorkers := runtime.NumCPU()
	jobs := make(chan []byte, numWorkers)
	results := make(chan []byte, numWorkers)
	errors := make(chan error, 1)

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerIV []byte) {
			defer wg.Done()
			stream := cipher.NewCTR(block, workerIV)
			for chunk := range jobs {
				decryptedChunk := make([]byte, len(chunk))
				stream.XORKeyStream(decryptedChunk, chunk)
				results <- decryptedChunk
			}
		}(incrementIV(iv))
	}

	go func() {
		defer close(jobs)
		for {
			chunk := make([]byte, chunkSize)
			n, err := bufReader.Read(chunk)
			if err != nil {
				if err != io.EOF {
					errors <- fmt.Errorf("error reading encrypted data: %v", err)
				}
				break
			}
			if n == 0 {
				break
			}
			jobs <- chunk[:n]
		}
	}()

	go func() {
		defer close(results)
		for decryptedChunk := range results {
			if _, err := bufWriter.Write(decryptedChunk); err != nil {
				errors <- fmt.Errorf("error writing decrypted data: %v", err)
				return
			}
		}
	}()

	wg.Wait()

	select {
	case err := <-errors:
		return err
	default:
	}

	duration := time.Since(startTime)
	logger.Log(fmt.Sprintf("Decryption completed. Duration: %v", duration))
	return nil
}

func incrementIV(iv []byte) []byte {
	newIV := make([]byte, len(iv))
	copy(newIV, iv)
	for i := len(newIV) - 1; i >= 0; i-- {
		newIV[i]++
		if newIV[i] != 0 {
			break
		}
	}
	return newIV
}