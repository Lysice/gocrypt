package test

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/lysice/gocrypt/constants"
	"github.com/lysice/gocrypt/encryption"
)

func TestMultipleEncryptorsSamePassword(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "shared-secret"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	// Create multiple encryptors with same config
	encryptors := make([]*encryption.ConfigStringEncryptor, 5)
	for i := 0; i < 5; i++ {
		encryptor, err := encryption.NewConfigStringEncryptor(config)
		if err != nil {
			t.Fatalf("Failed to create encryptor %d: %v", i, err)
		}
		encryptors[i] = encryptor
	}

	plaintext := "shared-secret-message"

	// Each encryptor should be able to encrypt
	encryptedValues := make([]string, len(encryptors))
	for i, encryptor := range encryptors {
		encrypted, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryptor %d failed to encrypt: %v", i, err)
		}
		encryptedValues[i] = encrypted

		// Each should be able to decrypt its own encryption
		decrypted, err := encryptor.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Encryptor %d failed to decrypt its own encryption: %v", i, err)
		}
		if decrypted != plaintext {
			t.Errorf("Encryptor %d: decrypted value doesn't match", i)
		}
	}

	// Any encryptor should be able to decrypt any other's encryption
	// (since they use the same password and algorithm)
	for i, encrypted := range encryptedValues {
		for j, decryptor := range encryptors {
			if i != j {
				decrypted, err := decryptor.Decrypt(encrypted)
				if err != nil {
					t.Errorf("Encryptor %d failed to decrypt encryptor %d's value: %v", j, i, err)
					continue
				}
				if decrypted != plaintext {
					t.Errorf("Cross-decryption failed: encryptor %d couldn't decrypt encryptor %d's value", j, i)
				}
			}
		}
	}
}

func TestConcurrentEncryption(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "concurrent-test"

	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	const numGoroutines = 10
	const numIterations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errs := make(chan error, numGoroutines*numIterations)

	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			defer wg.Done()

			for i := 0; i < numIterations; i++ {
				plaintext := strings.Repeat("X", id*10+i)
				encrypted, err := encryptor.Encrypt(plaintext)
				if plaintext == "" {
					if err == nil {
						errs <- errors.New("text is empty should have an error")
					}
					continue
				}
				if err != nil {
					errs <- err
					continue
				}

				decrypted, err := encryptor.Decrypt(encrypted)
				if err != nil {
					errs <- err
					continue
				}

				if decrypted != plaintext {
					errs <- &DecryptionError{id, i, plaintext, decrypted}
				}
			}
		}(g)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("Concurrent test error: %v", err)
	}
}

// Helper error type for concurrent tests
type DecryptionError struct {
	GoroutineID int
	Iteration   int
	Expected    string
	Actual      string
}

func (e *DecryptionError) Error() string {
	return "Decryption mismatch"
}

func TestEncryptorReuse(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "reuse-test"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Reuse the same encryptor multiple times
	messages := []string{
		"first message",
		"second message",
		"third message",
		"fourth message",
		"fifth message",
	}

	encryptedMessages := make([]string, len(messages))

	for i, msg := range messages {
		encrypted, err := encryptor.Encrypt(msg)
		if err != nil {
			t.Fatalf("Failed to encrypt message %d: %v", i, err)
		}
		encryptedMessages[i] = encrypted

		// Immediately decrypt
		decrypted, err := encryptor.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Failed to decrypt message %d: %v", i, err)
		}

		if decrypted != msg {
			t.Errorf("Message %d doesn't match after decryption", i)
		}
	}

	// Decrypt all messages again
	for i, encrypted := range encryptedMessages {
		decrypted, err := encryptor.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Failed to re-decrypt message %d: %v", i, err)
		}

		if decrypted != messages[i] {
			t.Errorf("Message %d doesn't match after re-decryption", i)
		}
	}
}

func TestInvalidEncryptedData(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "test"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Test invalid base64
	invalidCases := []string{
		"ENC(not-valid-base64!)",
		"ENC(==invalid==)", // 无效的base64
		"ENC(123!@#)",      // 包含非法字符
		"ENC(abc)",         // 长度不是4的倍数
	}

	for _, invalid := range invalidCases {
		_, err := encryptor.Decrypt(invalid)
		if err == nil {
			t.Errorf("Should fail to decrypt invalid data: %q", invalid)
		}
	}

	// Test valid base64 but invalid encrypted data
	validBase64ButInvalid := []string{
		"ENC(" + strings.Repeat("A", 10) + ")", // 太短
		"ENC(AAAAAAAAAAA=)",                    // 长度不足
	}

	for _, testCase := range validBase64ButInvalid {
		_, err := encryptor.Decrypt(testCase)
		if err == nil {
			t.Errorf("Should fail to decrypt invalid encrypted data: %q", testCase)
		}
	}
}

func TestFullIntegration(t *testing.T) {
	// 测试完整的使用场景
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "integration-test-key"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// 测试1: 简单的加密解密
	t.Run("BasicEncryption", func(t *testing.T) {
		plaintext := "my-secret-password"
		encrypted, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		if !encryptor.IsEncrypted(encrypted) {
			t.Error("Should be detected as encrypted")
		}

		decrypted, err := encryptor.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if decrypted != plaintext {
			t.Errorf("Data mismatch: got %q, want %q", decrypted, plaintext)
		}
	})

	// 测试2: 配置文件场景
	t.Run("ConfigurationFiles", func(t *testing.T) {
		configData := map[string]string{
			"database.password": "db-secret-123",
			"api.key":           "api-key-456",
			"redis.password":    "redis-pass-789",
		}

		encryptedConfig := make(map[string]string)
		for k, v := range configData {
			encrypted, err := encryptor.Encrypt(v)
			if err != nil {
				t.Fatalf("Failed to encrypt %s: %v", k, err)
			}
			encryptedConfig[k] = encrypted
		}

		// 模拟从配置文件读取
		for k, encrypted := range encryptedConfig {
			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Failed to decrypt %s: %v", k, err)
			}

			if decrypted != configData[k] {
				t.Errorf("Config mismatch for %s: got %q, want %q",
					k, decrypted, configData[k])
			}
		}
	})

	// 测试3: JSON配置
	t.Run("JSONConfiguration", func(t *testing.T) {
		appConfig := struct {
			Database struct {
				URL      string `json:"url"`
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"database"`
		}{
			Database: struct {
				URL      string `json:"url"`
				Username string `json:"username"`
				Password string `json:"password"`
			}{
				URL:      "jdbc:mysql://localhost:3306/mydb",
				Username: "admin",
				Password: "ENC(encrypted-password-here)",
			},
		}

		// 在实际使用中，您会解密配置值
		jsonData, _ := json.Marshal(appConfig)
		t.Logf("Sample JSON config: %s", string(jsonData))

		var m = map[string]string{
			"url":      appConfig.Database.URL,
			"username": appConfig.Database.Username,
			"password": appConfig.Database.Password,
		}

		for k, v := range m {
			encrypted, err := encryptor.Encrypt(v)
			if err != nil {
				t.Fatalf("Failed to decrypt %s: %v", k, err)
			}

			decrypted, err := encryptor.Decrypt(encrypted)
			if decrypted != v {
				t.Fatalf("Data mismatch: got %q, want %q", decrypted, v)
			}
		}
	})
}
