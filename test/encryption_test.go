package test

import (
	"strings"
	"testing"

	"github.com/lysice/gocrypt/constants"
	"github.com/lysice/gocrypt/encryption"
)

func TestEncryptionDecryption(t *testing.T) {
	testCases := []struct {
		name       string
		algorithm  string
		password   string
		plaintext  string
		shouldFail bool
	}{
		{
			name:       "AES-256 simple password",
			algorithm:  constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			password:   "test-password-123",
			plaintext:  "secret-data",
			shouldFail: false,
		},
		{
			name:       "AES-256 with special chars",
			algorithm:  constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			password:   "p@ssw0rd!#$%",
			plaintext:  "my-p@ssw0rd!#$%",
			shouldFail: false,
		},
		{
			name:       "DES with unicode",
			algorithm:  constants.AlgorithmPBEWithMD5AndDES.String(),
			password:   "test",
			plaintext:  "测试密码🔐",
			shouldFail: false,
		},
		{
			name:       "Empty string",
			algorithm:  constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			password:   "test",
			plaintext:  "",
			shouldFail: true,
		},
		{
			name:       "Single character",
			algorithm:  constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			password:   "test",
			plaintext:  "a",
			shouldFail: false,
		},
		{
			name:      "Very long text",
			algorithm: constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			password:  "test",
			plaintext: "This is a very long secret message that needs to be encrypted properly. " +
				strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 100),
			shouldFail: false,
		},
		{
			name:       "New lines and tabs",
			algorithm:  constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			password:   "test",
			plaintext:  "Line1\nLine2\tTab\nLine3\r\nWindows",
			shouldFail: false,
		},
		{
			name:       "Special characters",
			algorithm:  constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			password:   "test",
			plaintext:  "!@#$%^&*()_+-=[]{}|;:,.<>?/~`",
			shouldFail: false,
		},
		{
			name:       "Control characters",
			algorithm:  constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			password:   "test",
			plaintext:  string([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}),
			shouldFail: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := encryption.NewPasswordEncryptorConfig()
			config.Password = tc.password
			config.Algorithm = tc.algorithm

			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			// Test encryption
			encrypted, err := encryptor.Encrypt(tc.plaintext)

			if tc.shouldFail {
				if err == nil {
					t.Fatalf("Encryption should fail but it succeeded.")
				}
				return
			}

			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify ENC() wrapper
			if !encryption.IsEncrypted(encrypted) {
				t.Error("Encrypted value should be wrapped with ENC()")
			}

			// Test decryption
			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decrypted != tc.plaintext {
				t.Errorf("Decrypted value doesn't match. Got: %q, Want: %q", decrypted, tc.plaintext)
			}

			// Test that the same plaintext encrypted multiple times produces different results
			// (due to random salt and IV)
			encrypted2, err := encryptor.Encrypt(tc.plaintext)
			if err != nil {
				t.Fatalf("Second encryption failed: %v", err)
			}

			if encrypted == encrypted2 && tc.plaintext != "" {
				t.Error("Same plaintext should produce different encrypted values (random salt/IV)")
			}

			// Verify both encrypted values can be decrypted
			decrypted2, err := encryptor.Decrypt(encrypted2)
			if err != nil {
				t.Fatalf("Decryption of second encrypted value failed: %v", err)
			}

			if decrypted2 != tc.plaintext {
				t.Errorf("Second decrypted value doesn't match")
			}
		})
	}
}

func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"ENC(abc123)", true},
		{"ENC(ABC123)", true},
		{"ENC(1234567890)", true},
		{"abc123", false},
		{"ENC(abc123", false}, // 缺少右括号
		{"abc123)", false},    // 缺少左括号
		{"", false},
		{"ENC()", true},         // 空加密值
		{"ENC(  )", true},       // 空格
		{"ENC(a\nb)", true},     // 换行符
		{" ENC(abc123)", false}, // 前面有空格
		{"ENC(abc123) ", false}, // 后面有空格
	}

	for _, test := range tests {
		result := encryption.IsEncrypted(test.value)
		if result != test.expected {
			t.Errorf("IsEncrypted(%q) = %v, want %v", test.value, result, test.expected)
		}
	}
}

func TestExtractEncryptedValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasError bool
	}{
		{"ENC(abc123)", "abc123", false},
		{"ENC(ABC123)", "ABC123", false},
		{"abc123", "abc123", false}, // 不是ENC格式，返回原值
		{"", "", false},
		{"ENC()", "", false},     // 空加密值
		{"ENC(  )", "  ", false}, // 空格
	}

	for _, test := range tests {
		result, err := encryption.ExtractEncryptedValue(test.input)
		if test.hasError && err == nil {
			t.Errorf("ExtractEncryptedValue(%q) expected error, got none", test.input)
		}
		if !test.hasError && err != nil {
			t.Errorf("ExtractEncryptedValue(%q) unexpected error: %v", test.input, err)
		}
		if result != test.expected {
			t.Errorf("ExtractEncryptedValue(%q) = %q, want %q", test.input, result, test.expected)
		}
	}
}

func TestOutputTypes(t *testing.T) {
	outputTypes := []string{constants.OutputTypeBase64.String(), constants.OutputTypeHex.String()}

	for _, outputType := range outputTypes {
		t.Run(outputType, func(t *testing.T) {
			config := encryption.NewPasswordEncryptorConfig()
			config.Password = "test"
			config.StringOutputType = outputType

			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			plaintext := "test-data"
			encrypted, err := encryptor.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// 验证输出格式
			inner := strings.TrimPrefix(encrypted, "ENC(")
			inner = strings.TrimSuffix(inner, ")")

			switch outputType {
			case constants.OutputTypeBase64.String():
				// Base64应该只包含特定字符
				validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
				for _, ch := range inner {
					if !strings.ContainsRune(validChars, ch) {
						t.Errorf("Invalid base64 character: %c", ch)
					}
				}
			case constants.OutputTypeHex.String():
				// Hex应该只包含0-9, a-f, A-F
				validChars := "0123456789abcdefABCDEF"
				for _, ch := range inner {
					if !strings.ContainsRune(validChars, ch) {
						t.Errorf("Invalid hex character: %c", ch)
					}
				}
				// Hex长度应该是偶数
				if len(inner)%2 != 0 {
					t.Errorf("Hex string should have even length, got %d", len(inner))
				}
			}

			// 验证能正确解密
			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decrypted != plaintext {
				t.Errorf("Decrypted value doesn't match")
			}
		})
	}
}

func TestEmptyPassword(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "" // 空密码

	_, err := encryption.NewConfigStringEncryptor(config)
	if err == nil {
		t.Error("Should fail with empty password")
	}

	// 验证错误信息
	if err != nil && !strings.Contains(err.Error(), "password") {
		t.Errorf("Expected error about password, got: %v", err)
	}
}

func TestInvalidAlgorithm(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "test"
	config.Algorithm = "INVALID_ALGORITHM"

	_, err := encryption.NewConfigStringEncryptor(config)
	if err == nil {
		t.Error("Should fail with invalid algorithm")
	}
}

func TestInvalidSaltSize(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "test"
	config.SaltSize = 0

	_, err := encryption.NewConfigStringEncryptor(config)
	if err == nil {
		t.Error("Should fail with zero salt size")
	}
}

func TestInvalidIterations(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "test"
	config.KeyObtentionIterations = 0

	_, err := encryption.NewConfigStringEncryptor(config)
	if err == nil {
		t.Error("Should fail with zero iterations")
	}
}
