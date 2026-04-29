package test

import (
	"strings"
	"testing"

	"github.com/lysice/gocrypt/constants"
	"github.com/lysice/gocrypt/encryption"
)

func TestAlgorithmCompatibility(t *testing.T) {
	algorithms := []struct {
		name   string
		config func(*encryption.PasswordEncryptorConfig)
	}{
		{
			name: constants.AlgorithmPBEWithMD5AndDES.String(),
			config: func(c *encryption.PasswordEncryptorConfig) {
				c.Algorithm = constants.AlgorithmPBEWithMD5AndDES.String()
				c.SaltSize = 8
				c.KeyObtentionIterations = 1000
			},
		},
		{
			name: constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			config: func(c *encryption.PasswordEncryptorConfig) {
				c.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()
				c.SaltSize = 16
				c.KeyObtentionIterations = 1000
			},
		},
	}

	for _, algo := range algorithms {
		t.Run(algo.name, func(t *testing.T) {
			config := encryption.NewPasswordEncryptorConfig()
			config.Password = "test-password-for-" + algo.name
			algo.config(config)

			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor with algorithm %s: %v", algo.name, err)
			}

			// 测试多种长度的明文
			testMessages := []string{
				"",                                // 空字符串
				"a",                               // 单个字符
				"short",                           // 短字符串
				"This is a medium length message", // 中等长度
				strings.Repeat("A", 1000),         // 长字符串
				"!@#$%^&*()_+",                    // 特殊字符
				"测试中文",                            // 中文
				"🎉🔐💻",                             // 表情符号
			}

			for i, plaintext := range testMessages {
				t.Run(plaintext, func(t *testing.T) {
					encrypted, err := encryptor.Encrypt(plaintext)
					if plaintext == "" {
						if err == nil {
							t.Error("Plaintext encrypt should have failed")
						}
						return
					}
					if err != nil {
						t.Errorf("Test %d: Encryption failed: %v", i, err)
						return
					}

					decrypted, err := encryptor.Decrypt(encrypted)
					if err != nil {
						t.Errorf("Test %d: Decryption failed: %v", i, err)
						return
					}

					if decrypted != plaintext {
						t.Errorf("Test %d: Decrypted value doesn't match. Got: %q, Want: %q",
							i, decrypted, plaintext)
					}
				})
			}
		})
	}
}

func TestDifferentPasswords(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	passwords := []string{
		"short",
		"very-long-password-with-special-chars!@#$%^&*()",
		"12345678901234567890123456789012", // 32字节
		"测试密码",                             // 中文密码
		"p@ssw0rd!",                        // 常用密码格式
	}

	plaintext := "This is a secret message"

	for _, password := range passwords {
		t.Run(password, func(t *testing.T) {
			config.Password = password
			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			encrypted, err := encryptor.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decrypted != plaintext {
				t.Error("Decrypted value doesn't match")
			}
		})
	}
}

func TestSaltVariations(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()
	config.Password = "test"

	saltSizes := []int{8, 16, 32, 64}
	plaintext := "Test message"

	for _, saltSize := range saltSizes {
		t.Run(string(rune(saltSize)), func(t *testing.T) {
			config.SaltSize = saltSize
			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			encrypted, err := encryptor.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decrypted != plaintext {
				t.Error("Decrypted value doesn't match")
			}
		})
	}
}

func TestIterationVariations(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()
	config.Password = "test"

	iterations := []int{1, 10, 100, 1000, 10000}
	plaintext := "Test message"

	for _, iter := range iterations {
		t.Run(string(rune(iter)), func(t *testing.T) {
			config.KeyObtentionIterations = iter
			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			encrypted, err := encryptor.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decrypted != plaintext {
				t.Error("Decrypted value doesn't match")
			}
		})
	}
}
