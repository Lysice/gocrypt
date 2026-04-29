package main

import (
	"fmt"
	"log"

	"github.com/lysice/gocrypt/encryption"
)

// 模拟应用程序配置
type AppConfig struct {
	Database struct {
		URL      string
		Username string
		Password string
	}
	Redis struct {
		Host     string
		Port     int
		Password string
	}
	API struct {
		Key    string
		Secret string
	}
}

func main() {
	fmt.Println("=== Gocrypt Configuration Example ===")

	// 创建加密器
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "app-config-secret-key"

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		log.Fatal(err)
	}

	// 模拟加密的配置
	encryptedConfig := map[string]string{
		"database.url":      "ENC(m6U2e8n9p5q7r3s1t5v7x9z1b3d5f7h9j1l3n5p7r9t1v3x5z7b9d1f3h5)",
		"database.username": "ENC(a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6)",
		"database.password": "ENC(p4s5w6o7r8d9!@#$%^&*()_+-=[]{}|;:,.<>?)",
		"redis.password":    "ENC(r3d4i5s6p7a8s9s0w1o2r3d4!@#)",
		"api.key":           "ENC(k3e4y5!@#$%^&*()_+[]{}|;:,.<>?)",
		"api.secret":        "ENC(s5e6c7r8e9t0!@#$%^&*()_+[]{}|;:,.<>?)",
	}

	// 解密配置
	fmt.Println("\nDecrypting configuration...")
	for key, value := range encryptedConfig {
		decrypted, err := encryptor.Decrypt(value)
		if err != nil {
			if encryption.IsEncrypted(value) {
				log.Printf("Failed to decrypt %s: %v", key, err)
				continue
			}
			decrypted = value
		}
		fmt.Printf("%s = %s\n", key, decrypted)
	}

	// 演示加密新配置
	fmt.Println("\nEncrypting new configuration values...")

	plainConfigs := map[string]string{
		"new.database.password": "NewPassword123!",
		"new.api.key":           "ApiKey-2024-Secret",
	}

	for key, value := range plainConfigs {
		encrypted, err := encryptor.Encrypt(value)
		if err != nil {
			log.Printf("Failed to encrypt %s: %v", key, err)
			continue
		}
		fmt.Printf("%s = %s\n", key, encrypted)
	}
}
