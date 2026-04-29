package test

import (
	"strings"
	"testing"

	"github.com/lysice/gocrypt/constants"
	"github.com/lysice/gocrypt/encryption"
)

func TestConfigStringEncryptor(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "my-secret-key"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Test that non-encrypted values are returned as-is
	plainValues := []string{
		"plain-text",
		"not-encrypted",
		"",
		"12345",
	}

	for _, value := range plainValues {
		decrypted, err := encryptor.Decrypt(value)
		if err != nil {
			t.Errorf("Failed to decrypt plain value %q: %v", value, err)
		}
		if decrypted != value {
			t.Errorf("Plain value should be returned as-is. Got: %q, Want: %q", decrypted, value)
		}
	}

	// Test that ENC() wrapper is added to encrypted values
	testData := []string{
		"password",
		"secret-key",
		"another-secret",
	}

	for _, plaintext := range testData {
		encrypted, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Errorf("Failed to encrypt %q: %v", plaintext, err)
			continue
		}

		if !strings.HasPrefix(encrypted, "ENC(") {
			t.Errorf("Encrypted value should start with ENC(: %q", encrypted)
		}
		if !strings.HasSuffix(encrypted, ")") {
			t.Errorf("Encrypted value should end with ): %q", encrypted)
		}

		// Decrypt and verify
		decrypted, err := encryptor.Decrypt(encrypted)
		if err != nil {
			t.Errorf("Failed to decrypt %q: %v", encrypted, err)
			continue
		}

		if decrypted != plaintext {
			t.Errorf("Decrypted value doesn't match. Got: %q, Want: %q", decrypted, plaintext)
		}
	}
}

func TestCustomDelimiters(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "test"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()
	config.Prefix = "CRYPT("
	config.Suffix = ")"

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	plaintext := "secret-data"
	encrypted, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Should use custom delimiters
	if !strings.HasPrefix(encrypted, "CRYPT(") {
		t.Errorf("Should use custom prefix. Got: %q", encrypted)
	}
	if !strings.HasSuffix(encrypted, ")") {
		t.Errorf("Should use custom suffix. Got: %q", encrypted)
	}

	// Should be detected as encrypted
	if encryption.IsEncrypted(encrypted) {
		t.Error("Package-level IsEncrypted should return false for custom delimiters")
	}

	// Should decrypt correctly
	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted value doesn't match")
	}
}

func TestDecryptProperties(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "config-secret"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Create test properties
	properties := map[string]string{
		"db.password": "my-db-password",
		"api.key":     "api-key-secret",
		"redis.pass":  "redis-pass-123",
		"plain.text":  "not-encrypted", // 明文字符串
	}

	// Encrypt all values
	encryptedProps := make(map[string]string)
	for k, v := range properties {
		encrypted, err := encryptor.Encrypt(v)
		if err != nil {
			t.Fatalf("Failed to encrypt %s: %v", k, err)
		}
		encryptedProps[k] = encrypted
	}

	// Test decrypting mixed properties
	mixedProps := map[string]string{
		"db.password": encryptedProps["db.password"],
		"api.key":     encryptedProps["api.key"],
		"redis.pass":  encryptedProps["redis.pass"],
		"plain.text":  properties["plain.text"], // 保持明文
		"empty.value": "",                       // 空值
	}

	// 注意：ConfigStringEncryptor 没有 DecryptProperties 方法
	// 我们需要单独解密每个值
	for key, value := range mixedProps {
		decrypted, err := encryptor.Decrypt(value)
		if err != nil {
			t.Errorf("Failed to decrypt %s: %v", key, err)
			continue
		}

		// 获取预期值
		expected, ok := properties[key]
		if !ok {
			// 如果是测试中新增的键
			if key == "empty.value" {
				expected = ""
			} else {
				expected = value // 对于未知键，期望原值
			}
		}

		if decrypted != expected {
			t.Errorf("Property %s doesn't match. Got: %q, Want: %q",
				key, decrypted, expected)
		}
	}
}
