package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	generateKeys()

	message := []byte("Это секретное сообщение")

	signature, err := signMessage(message, "private_key.pem")
	if err != nil {
		log.Fatalf("Ошибка подписи сообщения: %v", err)
	}

	err = verifySignature(message, signature, "public_key.pem")
	if err != nil {
		log.Fatalf("Подпись недействительна: %v", err)
	}

	fmt.Println("Подпись успешно проверена!")
}

func generateKeys() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Ошибка генерации ключей: %v", err)
	}

	privateKeyFile, err := os.Create("private_key.pem")
	if err != nil {
		log.Fatalf("Ошибка создания файла закрытого ключа: %v", err)
	}
	defer privateKeyFile.Close()

	pem.Encode(privateKeyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	publicKeyFile, err := os.Create("public_key.pem")
	if err != nil {
		log.Fatalf("Ошибка создания файла открытого ключа: %v", err)
	}
	defer publicKeyFile.Close()

	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	pem.Encode(publicKeyFile, &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})
}

func signMessage(message []byte, privateKeyPath string) ([]byte, error) {
	privateKeyFile, err := os.Open(privateKeyPath)
	if err != nil {
		return nil, err
	}
	defer privateKeyFile.Close()

	pemBytes, err := io.ReadAll(privateKeyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("неверный формат закрытого ключа")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	hashed := crypto.SHA256.New()
	hashed.Write(message)
	hashedMessage := hashed.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashedMessage)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func verifySignature(message, signature []byte, publicKeyPath string) error {
	publicKeyFile, err := os.Open(publicKeyPath)
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	pemBytes, err := io.ReadAll(publicKeyFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("неверный формат открытого ключа")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return err
	}

	hashed := crypto.SHA256.New()
	hashed.Write(message)
	hashedMessage := hashed.Sum(nil)

	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashedMessage, signature)
}
