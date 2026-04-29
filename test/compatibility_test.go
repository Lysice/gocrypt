package test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/lysice/gocrypt/constants"
	"github.com/lysice/gocrypt/encryption"
)

// TestCompatibilityWithJavaJasypt 测试与Java Jasypt的兼容性
func TestCompatibilityWithJavaJasypt(t *testing.T) {
	// 测试1: 使用已知的Java Jasypt生成的加密值（如果可用）
	// 这里我们先测试自生成值的兼容性
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "test-password"
	config.Algorithm = constants.AlgorithmPBEWithMD5AndDES.String()
	config.SaltSize = 8
	config.Iterations = 1000
	config.StringOutputType = constants.OutputTypeBase64.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// 测试数据
	testCases := []struct {
		name      string
		plaintext string
	}{
		{"Simple text", "secret"},
		{"With spaces", "my secret password"},
		{"Special chars", "p@ssw0rd!"},
		{"Empty string", ""},
		{"Single char", "a"},
		{"Unicode", "测试密码🔐"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 加密
			encrypted, err := encryptor.Encrypt(tc.plaintext)
			if tc.plaintext == "" {
				if err == nil {
					t.Error("Expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// 验证格式
			if !strings.HasPrefix(encrypted, "ENC(") || !strings.HasSuffix(encrypted, ")") {
				t.Errorf("Invalid ENC() format: %s", encrypted)
			}

			// 提取加密值
			inner := strings.TrimPrefix(encrypted, "ENC(")
			inner = strings.TrimSuffix(inner, ")")

			// 验证base64格式
			_, err = base64.StdEncoding.DecodeString(inner)
			if err != nil {
				t.Errorf("Not valid base64: %v", err)
			}

			// 解密
			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decrypted != tc.plaintext {
				t.Errorf("Decrypted value doesn't match. Got: %q, Want: %q", decrypted, tc.plaintext)
			}
		})
	}
}

// TestAlgorithmSpecificCompatibility 测试不同算法的兼容性
func TestAlgorithmSpecificCompatibility(t *testing.T) {
	algorithms := []struct {
		name       string
		algorithm  string
		saltSize   int
		iterations int
	}{
		{
			name:       constants.AlgorithmPBEWithMD5AndDES.String(),
			algorithm:  constants.AlgorithmPBEWithMD5AndDES.String(),
			saltSize:   8,
			iterations: 1000,
		},
		{
			name:       constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			algorithm:  constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			saltSize:   16,
			iterations: 1000,
		},
	}

	for _, algo := range algorithms {
		t.Run(algo.name, func(t *testing.T) {
			config := encryption.NewPasswordEncryptorConfig()
			config.Password = "compatibility-test"
			config.Algorithm = algo.algorithm
			config.SaltSize = algo.saltSize
			config.Iterations = algo.iterations
			config.KeyObtentionIterations = algo.iterations

			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			// 测试不同长度的明文
			plaintexts := []string{
				"",
				"a",
				"ab",
				"abc",
				"abcd",
				"abcde",
				"abcdef",
				"abcdefg",
				"abcdefgh",
				"abcdefghi",
				"abcdefghij",
				strings.Repeat("A", 100),
				strings.Repeat("B", 1000),
			}

			for i, plaintext := range plaintexts {
				encrypted, err := encryptor.Encrypt(plaintext)
				if plaintext == "" {
					if err == nil {
						t.Error("Expected error, got none")
					}
					continue
				}

				if err != nil {
					t.Errorf("Test %d: Encryption failed: %v", i, err)
					continue
				}

				decrypted, err := encryptor.Decrypt(encrypted)
				if err != nil {
					t.Errorf("Test %d: Decryption failed: %v", i, err)
					continue
				}

				if decrypted != plaintext {
					t.Errorf("Test %d: Decrypted value doesn't match. Got: %q, Want: %q",
						i, decrypted, plaintext)
				}
			}
		})
	}
}

// TestBackwardCompatibility 测试向后兼容性
// 确保新版本能解密旧版本加密的数据
func TestBackwardCompatibility(t *testing.T) {
	// 这里可以存储一些用旧版本加密的测试数据
	// 对于新项目，我们可以先生成一些加密数据，然后确保它们能被解密

	// 生成测试数据并保存到文件，然后在后续版本中测试
	// 这里我们先测试当前版本的自兼容性

	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "backward-compat"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// 生成一些测试数据
	testData := []string{
		"legacy-password-1",
		"old-api-key",
		"deprecated-secret",
	}

	// 加密并存储（在实际项目中可以保存到文件）
	encryptedData := make([]string, len(testData))
	for i, data := range testData {
		encrypted, err := encryptor.Encrypt(data)
		if err != nil {
			t.Fatalf("Failed to encrypt test data %d: %v", i, err)
		}
		encryptedData[i] = encrypted

		// 立即解密验证
		decrypted, err := encryptor.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Failed to decrypt immediately: %v", err)
		}

		if decrypted != data {
			t.Errorf("Immediate decryption failed for data %d", i)
		}
	}

	// 模拟"未来版本"的解密
	// 使用相同的配置创建新的加密器
	newConfig := encryption.NewPasswordEncryptorConfig()
	newConfig.Password = "backward-compat"
	newConfig.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	newEncryptor, err := encryption.NewConfigStringEncryptor(newConfig)
	if err != nil {
		t.Fatalf("Failed to create new encryptor: %v", err)
	}

	// 用新的加密器解密旧数据
	for i, encrypted := range encryptedData {
		decrypted, err := newEncryptor.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Failed to decrypt with new encryptor: %v", err)
		}

		if decrypted != testData[i] {
			t.Errorf("Backward compatibility failed for data %d", i)
		}
	}
}

// TestConfigurationCompatibility 测试配置兼容性
func TestConfigurationCompatibility(t *testing.T) {
	testCases := []struct {
		name   string
		config func(*encryption.PasswordEncryptorConfig)
	}{
		{
			name: "Default config",
			config: func(c *encryption.PasswordEncryptorConfig) {
				// 使用默认值
			},
		},
		{
			name: "Custom salt size",
			config: func(c *encryption.PasswordEncryptorConfig) {
				c.SaltSize = 32
			},
		},
		{
			name: "Many iterations",
			config: func(c *encryption.PasswordEncryptorConfig) {
				c.KeyObtentionIterations = 10000
			},
		},
		{
			name: "Hex output",
			config: func(c *encryption.PasswordEncryptorConfig) {
				c.StringOutputType = constants.OutputTypeHex.String()
			},
		},
		{
			name: "Base64 output",
			config: func(c *encryption.PasswordEncryptorConfig) {
				c.StringOutputType = constants.OutputTypeBase64.String()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := encryption.NewPasswordEncryptorConfig()
			config.Password = "config-test"
			config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()
			tc.config(config)

			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			plaintext := "configuration test data"

			// 加密
			encrypted, err := encryptor.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// 解密
			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decrypted != plaintext {
				t.Errorf("Configuration %s failed", tc.name)
			}

			// 验证输出格式
			if config.StringOutputType == constants.OutputTypeHex.String() {
				inner := strings.TrimPrefix(encrypted, "ENC(")
				inner = strings.TrimSuffix(inner, ")")
				// 验证hex格式
				for _, ch := range strings.ToLower(inner) {
					if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
						t.Errorf("Invalid hex character: %c", ch)
					}
				}
			}
		})
	}
}
