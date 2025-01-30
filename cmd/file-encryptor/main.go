package main

import (
    "flag"
    "fmt"
    "os"
    "strings"

    "file-encryptor/pkg/crypto"
    "file-encryptor/pkg/fileops"
    "file-encryptor/pkg/logging"
)

func main() {
    logger := logging.NewLogger()
    logger.LogDebug("Starting file encryptor")

    encrypt := flag.Bool("e", false, "Encrypt the file")
    decrypt := flag.Bool("d", false, "Decrypt the file")

    // Define both short and long flag names for file and key
    file := flag.String("file", "", "File to encrypt or decrypt")
    flag.StringVar(file, "f", "", "File to encrypt or decrypt (shorthand)")
    key := flag.String("key", "", "Path to the key file")
    flag.StringVar(key, "k", "", "Path to the key file (shorthand)")

    password := flag.String("password", "", "Password for encryption/decryption (alternative to key file)")
    flag.StringVar(password, "p", "", "Password for encryption/decryption (shorthand)")

    generateKeys := flag.Bool("generate-keys", false, "Generate a new RSA key pair")
    keyBaseName := flag.String("key-name", "key", "Base name for the generated key files")

    flag.Parse()
    logger.LogDebug("Parsed command line flags")

    if *generateKeys && !*encrypt && *file == "" {
        if err := handleGenerateKeys(*keyBaseName, logger); err != nil {
            logger.LogError(err.Error())
            os.Exit(1)
        }
        logger.LogInfo("RSA Key pair generated successfully.")
        os.Exit(0)
    }

    // Validate the flags
    if err := validateFlags(*encrypt, *decrypt, *file, *key, *password, *generateKeys); err != nil {
        logger.LogError(err.Error())
        flag.Usage()
        os.Exit(1)
    }

    var err error
    var operation, outputFile string
    if *generateKeys && *encrypt && *file != "" {
        operation = "Encryption"
        outputFile, err = handleGenerateAndEncrypt(*keyBaseName, *file, logger)
    } else if *encrypt {
        operation = "Encryption"
        outputFile, err = handleEncryption(*file, *key, *password, logger)
    } else {
        operation = "Decryption"
        outputFile, err = handleDecryption(*file, *key, *password, logger)
    }

    if err != nil {
        logger.LogError(fmt.Sprintf("Error during %s: %v", strings.ToLower(operation), err))
        if strings.Contains(err.Error(), "security error") {
            fmt.Println("\n⚠️  Security Warning: File integrity check failed!")
            fmt.Println("    The file may have been tampered with or corrupted.")
            fmt.Println("    The decrypted file has been deleted for security reasons.")
        } else if os.IsNotExist(err) {
            logger.LogInfo("Please check if the specified file and key exist and are readable.")
        }
        os.Exit(1)
    }

    logger.LogInfo(fmt.Sprintf("%s completed successfully. Output file: %s", operation, outputFile))
    logger.LogDebug("Operation completed")
}

func validateFlags(encrypt, decrypt bool, file, key, password string, generateKeys bool) error {
    if generateKeys && encrypt && file == "" {
        return fmt.Errorf("the --generate-keys flag requires the -f option to encrypt after generation")
    }

    if generateKeys {
        if decrypt || key != "" || password != "" {
            return fmt.Errorf("the --generate-keys flag cannot be combined with decrypt, key or password options")
        }
    }

    if (encrypt && decrypt) || (!encrypt && !decrypt) {
        return fmt.Errorf("please specify either -e for encryption or -d for decryption")
    }

    if file == "" && !generateKeys {
        return fmt.Errorf("please provide the --file or -f argument")
    }

    if key == "" && password == "" && !generateKeys {
        return fmt.Errorf("please provide either --key or -k or --password or -p argument")
    }

    if key != "" && password != "" {
        return fmt.Errorf("please provide either --key or -k or --password or -p, not both")
    }

    return nil
}

func handleGenerateKeys(keyBaseName string, logger *logging.Logger) error {
    logger.LogInfo("Starting RSA key pair generation")

    if err := crypto.GenerateRSAKeyPair(keyBaseName, logger); err != nil {
        return fmt.Errorf("failed to generate RSA key pair: %w", err)
    }

    logger.LogInfo("RSA key pair generated successfully.")
    return nil
}

func handleGenerateAndEncrypt(keyBaseName string, file string, logger *logging.Logger) (string, error) {
    logger.LogInfo("Starting RSA key pair generation and file encryption")

    // Generate the key pair
    privateKeyName, publicKeyName, err := crypto.GenerateRSAKeyPairWithNames(keyBaseName, logger)
    if err != nil {
        return "", fmt.Errorf("failed to generate RSA key pair: %w", err)
    }

    // Create encryptor using the public key
    encryptor, err := crypto.NewRSAEncryptor(publicKeyName)
    if err != nil {
        return "", fmt.Errorf("failed to create encryptor: %w", err)
    }

    // Calculate and log original file hash before encryption
    if hash, err := crypto.CalculateFileHash(file); err == nil {
        logger.LogDebug(fmt.Sprintf("Original file hash: %s", hash))
    }

    // Encrypt the file
    outputFile := file + ".enc"
    err = fileops.EncryptFile(file, outputFile, encryptor, logger)
    if err != nil {
        return "", err
    }

    // Log the key locations
    logger.LogInfo(fmt.Sprintf("Private key saved to: %s", privateKeyName))
    logger.LogInfo(fmt.Sprintf("Public key saved to: %s", publicKeyName))
    logger.LogInfo("Keep the private key secure - you will need it to decrypt the file!")

    return outputFile, nil
}

func handleEncryption(file, key, password string, logger *logging.Logger) (string, error) {
    logger.LogInfo("Starting file encryption")
    var encryptor crypto.Encryptor
    var err error

    if key != "" {
        encryptor, err = crypto.NewRSAEncryptor(key)
    } else {
        encryptor, err = crypto.NewPasswordEncryptor(password)
    }
    logger.LogDebugf("Initialized encryptor: %T", encryptor)

    if err != nil {
        return "", fmt.Errorf("error initializing encryptor: %v", err)
    }

    // Calculate and log original file hash before encryption
    if hash, err := crypto.CalculateFileHash(file); err == nil {
        logger.LogDebug(fmt.Sprintf("Original file hash: %s", hash))
    }

    outputFile := file + ".enc"
    err = fileops.EncryptFile(file, outputFile, encryptor, logger)
    if err != nil {
        return "", err
    }

    return outputFile, nil
}

func handleDecryption(file, key, password string, logger *logging.Logger) (string, error) {
    logger.LogInfo("Starting file decryption")
    var decryptor crypto.Decryptor
    var err error

    if key != "" {
        decryptor, err = crypto.NewRSADecryptor(key)
    } else {
        decryptor, err = crypto.NewPasswordDecryptor(password)
    }
    logger.LogDebugf("Initialized decryptor: %T", decryptor)

    if err != nil {
        return "", fmt.Errorf("error initializing decryptor: %v", err)
    }

    outputFile := strings.TrimSuffix(file, ".enc")
    err = fileops.DecryptFile(file, outputFile, decryptor, logger)
    if err != nil {
        // Check for integrity validation error
        if strings.Contains(err.Error(), "file integrity check failed") {
            return "", fmt.Errorf("security error: %v", err)
        }
        return "", err
    }

    // Log the hash of the decrypted file
    if hash, err := crypto.CalculateFileHash(outputFile); err == nil {
        logger.LogDebug(fmt.Sprintf("Decrypted file hash: %s", hash))
    }

    return outputFile, nil
}
