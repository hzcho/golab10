package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
)

const key = "achisisipopa"

func hashMD5(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum([]byte(key)))
}

func hashSHA256(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum([]byte(key)))
}

func hashSHA512(data string) string {
	h := sha512.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum([]byte(key)))
}

func main() {
	var input string
	var algorithm string

	fmt.Println("Введите строку для хэширования:")
	fmt.Scanln(&input)

	fmt.Println("Выберите алгоритм (md5, sha256, sha512):")
	fmt.Scanln(&algorithm)

	var hash string
	switch algorithm {
	case "md5":
		hash = hashMD5(input)
	case "sha256":
		hash = hashSHA256(input)
	case "sha512":
		hash = hashSHA512(input)
	default:
		fmt.Println("Неизвестный алгоритм")
		os.Exit(1)
	}

	fmt.Printf("Хэш: %s\n", hash)

	var inputHash string
	fmt.Println("Введите хэш для проверки целостности:")
	fmt.Scanln(&inputHash)

	if inputHash == hash {
		fmt.Println("Хэши совпадают. Данные целостны.")
	} else {
		fmt.Println("Хэши не совпадают. Данные повреждены.")
	}
}
