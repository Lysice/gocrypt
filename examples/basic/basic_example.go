package main

import (
	"fmt"
	"log"

	"github.com/lysice/gocrypt/constants"
	"github.com/lysice/gocrypt/encryption"
)

func main() {
	fmt.Println("=== Gocrypt-Go Basic Example ===")

	// 创建配置
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "my-secret-password-123"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()
	config.Iterations = 1000

	// 创建加密器
	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		log.Fatal(err)
	}

	// 测试数据
	testData := []string{
		"my-database-password",
		"Secret123!@#",
		"这是一个测试密码",
		"LongPasswordWithSpecialChars!@#$%^&*()",
	}

	for i, plaintext := range testData {
		fmt.Printf("\nTest %d:\n", i+1)
		fmt.Printf("  Plaintext: %s\n", plaintext)

		// 加密
		encrypted, err := encryptor.Encrypt(plaintext)
		if err != nil {
			log.Printf("  Encryption error: %v", err)
			continue
		}
		fmt.Printf("  Encrypted: %s\n", encrypted)

		// 检查是否加密
		if encryption.IsEncrypted(encrypted) {
			fmt.Println("  ✓ Is encrypted")
		}

		// 解密
		decrypted, err := encryptor.Decrypt(encrypted)
		if err != nil {
			log.Printf("  Decryption error: %v", err)
			continue
		}
		fmt.Printf("  Decrypted: %s\n", decrypted)

		// 验证
		if decrypted == plaintext {
			fmt.Println("  ✓ Decryption successful")
		} else {
			fmt.Println("  ✗ Decryption failed")
		}
	}

	fmt.Println("\n=== Algorithm Compatibility Test ===")

	// 测试不同算法
	algorithms := []string{
		constants.AlgorithmPBEWithMD5AndDES.String(),
		constants.AlgorithmPBEWithSHA1AndDESede.String(),
		constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
	}

	for _, algo := range algorithms {
		fmt.Printf("\nTesting algorithm: %s\n", algo)

		config.Algorithm = algo
		encryptor, err := encryption.NewConfigStringEncryptor(config)
		if err != nil {
			log.Printf("  Failed to create encryptor: %v", err)
			continue
		}

		plaintext := "TestPassword123"
		encrypted, err := encryptor.Encrypt(plaintext)
		if err != nil {
			log.Printf("  Encryption failed: %v", err)
			continue
		}

		decrypted, err := encryptor.Decrypt(encrypted)
		if err != nil {
			log.Printf("  Decryption failed: %v", err)
			continue
		}

		if decrypted == plaintext {
			fmt.Printf("  ✓ Algorithm %s works correctly\n", algo)
		} else {
			fmt.Printf("  ✗ Algorithm %s failed\n", algo)
		}
	}
}
