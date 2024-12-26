package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"os"
)

const privateKeyFile = "private_key.pem"
const dsn = "rsa_test:test1234@tcp(127.0.0.1:3306)/rsa_test"

func main() {
	// Define a flag for the message input
	message := flag.String("message", "", "The message to encrypt")
	encrypt := flag.Bool("encrypt", true, "The encrypt flag to encrypt or decrypt the message")
	flag.Parse()

	if *message == "" && *encrypt == true {
		fmt.Println("Please provide a message to encrypt using the -message flag.")
		return
	}

	var privateKey *rsa.PrivateKey

	// Check if the private key file exists
	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		// Generate RSA keys
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Println("Error generating RSA key:", err)
			return
		}

		// Save the private key to a file
		err = savePrivateKeyToFile(privateKey, privateKeyFile)
		if err != nil {
			fmt.Println("Error saving private key to file:", err)
			return
		}
	} else {
		// Load the private key from the file
		privateKey, err = loadPrivateKeyFromFile(privateKeyFile)
		if err != nil {
			fmt.Println("Error loading private key from file:", err)
			return
		}
	}

	publicKey := &privateKey.PublicKey

	// Encrypt the message
	if *encrypt == true {
		ciphertext, err := encryptOAEP([]byte(*message), publicKey)
		if err != nil {
			fmt.Println("Error encrypting message:", err)
			return
		}

		// Save the encrypted string to the database
		err = saveEncryptedMessageToDB(ciphertext)
		if err != nil {
			fmt.Println("Error saving encrypted message to database:", err)
			return
		}

		fmt.Println("Encrypted message saved to database successfully.")
	} else {
		// Load the encrypted string from the database
		ciphertext, err := loadEncryptedMessageFromDB()
		if err != nil {
			fmt.Println("Error loading encrypted message from database:", err)
			return
		}

		// Decrypt the message
		plaintext, err := decryptOAEP(ciphertext, privateKey)
		if err != nil {
			fmt.Println("Error decrypting message:", err)
			return
		}
		fmt.Printf("Decrypted message: %s\n", plaintext)
	}

}

func savePrivateKeyToFile(privateKey *rsa.PrivateKey, filename string) error {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return os.WriteFile(filename, privateKeyPEM, 0600)
}

func loadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	privateKeyPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func encryptOAEP(message []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, message, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func decryptOAEP(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func saveEncryptedMessageToDB(ciphertext []byte) error {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO messages (encrypted_message) VALUES (?)", hex.EncodeToString(ciphertext))
	return err
}

func loadEncryptedMessageFromDB() ([]byte, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var encryptedMessageHex string
	err = db.QueryRow("SELECT encrypted_message FROM messages ORDER BY id DESC LIMIT 1").Scan(&encryptedMessageHex)
	if err != nil {
		return nil, err
	}

	return hex.DecodeString(encryptedMessageHex)
}
