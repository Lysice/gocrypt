package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/lysice/gocrypt/encryption"
)

func main() {
	// 定义命令行参数
	password := flag.String("password", "", "Encryption password (required)")
	algorithm := flag.String("algorithm", "PBEWithHMACSHA256AndAES_256", "Encryption algorithm")
	iterations := flag.Int("iterations", 1000, "Key obtention iterations")
	action := flag.String("action", "", "Action: encrypt or decrypt (required)")
	value := flag.String("value", "", "Value to encrypt/decrypt (required)")
	saltSize := flag.Int("salt-size", 16, "Salt size in bytes")
	outputType := flag.String("output-type", "base64", "Output type: base64 or hex")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Gocrypt CLI - Gocrypt compatible encryption tool\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  Encrypt: %s -action encrypt -password secret -value 'my-password'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Decrypt: %s -action decrypt -password secret -value 'ENC(encrypted-string)'\n", os.Args[0])
	}

	flag.Parse()

	// 验证参数
	if *password == "" || *action == "" || *value == "" {
		flag.Usage()
		os.Exit(1)
	}

	// 创建配置
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = *password
	config.Algorithm = *algorithm
	config.KeyObtentionIterations = *iterations
	config.SaltSize = *saltSize
	config.StringOutputType = *outputType

	// 创建加密器
	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		log.Fatal("Failed to create encryptor:", err)
	}

	// 执行操作
	switch strings.ToLower(*action) {
	case "encrypt":
		result, err := encryptor.Encrypt(*value)
		if err != nil {
			log.Fatal("Encryption failed:", err)
		}
		fmt.Println(result)

	case "decrypt":
		result, err := encryptor.Decrypt(*value)
		if err != nil {
			log.Fatal("Decryption failed:", err)
		}
		fmt.Println(result)

	default:
		log.Fatal("Invalid action. Use 'encrypt' or 'decrypt'")
	}
}
