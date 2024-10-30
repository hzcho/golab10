package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

func pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func unpad(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("некорректный размер данных")
	}
	return data[:(length - unpadding)], nil
}

func encrypt(plainText string, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	paddedText := pad([]byte(plainText))
	cipherText := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, paddedText)

	return base64.StdEncoding.EncodeToString(iv) + ":" + base64.StdEncoding.EncodeToString(cipherText), nil
}

func decrypt(cipherText string, key string) (string, error) {
	parts := strings.Split(cipherText, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("некорректный формат шифротекста")
	}

	iv, _ := base64.StdEncoding.DecodeString(parts[0])
	cipherTextBytes, _ := base64.StdEncoding.DecodeString(parts[1])

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherTextBytes, cipherTextBytes)

	unpaddedText, err := unpad(cipherTextBytes)
	if err != nil {
		return "", err
	}

	return string(unpaddedText), nil
}

func main() {
	var input string
	var key string

	fmt.Println("Введите строку для шифрования:")
	fmt.Scanln(&input)

	fmt.Println("Введите секретный ключ (16, 24 или 32 байта):")
	fmt.Scanln(&key)

	encrypted, err := encrypt(input, key)
	if err != nil {
		fmt.Println("Ошибка шифрования:", err)
		return
	}
	fmt.Println("Зашифрованный текст:", encrypted)

	decrypted, err := decrypt(encrypted, key)
	if err != nil {
		fmt.Println("Ошибка расшифрования:", err)
		return
	}
	fmt.Println("Расшифрованный текст:", decrypted)
}
