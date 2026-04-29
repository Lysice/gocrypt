package test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/lysice/gocrypt/constants"
	"github.com/lysice/gocrypt/encryption"
)

func TestEdgeCases(t *testing.T) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "edge-cases-test"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// 测试各种边缘情况
	testCases := []struct {
		name       string
		plaintext  string
		shouldFail bool
	}{
		// 空字符串应该失败
		{"Empty string", "", true},

		// 其他测试用例应该成功
		{"Single null byte", "\x00", false},
		{"Single space", " ", false},
		{"Tab", "\t", false},
		{"Newline", "\n", false},
		{"Carriage return", "\r", false},
		{"Form feed", "\f", false},
		{"Vertical tab", "\v", false},

		// 特殊字符
		{"All control chars", "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", false},
		{"Extended ASCII", "\x80\x81\x82\x83\x84\x85\x86\x87", false},
		{"Unicode BMP", "Hello 世界", false},
		{"Unicode SMP", "🎉🎊🎈", false},
		{"Mixed unicode", "Hello 世界 🎉 test", false},

		// 边界长度
		{"Length 1", "a", false},
		{"Length 2", "ab", false},
		{"Length 3", "abc", false},
		{"Length 4", "abcd", false},
		{"Length 7", "abcdefg", false},
		{"Length 8", "abcdefgh", false},
		{"Length 9", "abcdefghi", false},
		{"Length 15", "abcdefghijklmno", false},
		{"Length 16", "abcdefghijklmnop", false},
		{"Length 17", "abcdefghijklmnopq", false},

		// 重复模式
		{"All zeros", strings.Repeat("0", 100), false},
		{"All ones", strings.Repeat("1", 100), false},
		{"Alternating", strings.Repeat("01", 50), false},
		{"Incrementing", "abcdefghijklmnopqrstuvwxyz", false},

		// 文件路径和URL
		{"File path", "/usr/local/bin/program", false},
		{"Windows path", "C:\\Program Files\\App\\data.txt", false},
		{"URL", "https://example.com/path?query=value&key=secret", false},
		{"JSON", `{"password": "secret", "api_key": "12345"}`, false},
		{"XML", `<config><password>secret</password></config>`, false},

		// 特殊编码
		{"Base64 like", "SGVsbG8gV29ybGQ=", false},
		{"Hex like", "48656c6c6f20576f726c64", false},
		{"UUID", "123e4567-e89b-12d3-a456-426614174000", false},
		{"JWT header", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", false},

		// 语言特定
		{"Chinese", "这是一个测试密码", false},
		{"Japanese", "テストパスワード", false},
		{"Korean", "테스트 비밀번호", false},
		{"Arabic", "كلمة المرور الاختبار", false},
		{"Emoji", "🔐🗝️🔑🎯✅", false},

		// 组合
		{"Mixed everything", "Test123!@# 世界 🌍 \n\t\r", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 验证UTF-8有效性
			if !utf8.ValidString(tc.plaintext) {
				t.Skipf("Skipping invalid UTF-8: %q", tc.plaintext)
			}

			// 加密
			encrypted, err := encryptor.Encrypt(tc.plaintext)

			if tc.shouldFail {
				// 应该失败
				if err == nil {
					t.Error("Expected encryption to fail for empty string, but it succeeded")
				}
				return
			}

			// 不应该失败
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// 验证格式
			if !strings.HasPrefix(encrypted, "ENC(") || !strings.HasSuffix(encrypted, ")") {
				t.Errorf("Invalid ENC() format: %s", encrypted)
			}

			// 解密
			decrypted, err := encryptor.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// 验证结果
			if decrypted != tc.plaintext {
				t.Errorf("Decrypted value doesn't match.\nGot:  %q\nWant: %q",
					decrypted, tc.plaintext)

				// 打印详细信息
				t.Logf("Original length: %d", len(tc.plaintext))
				t.Logf("Decrypted length: %d", len(decrypted))

				// 显示差异
				for i := 0; i < len(tc.plaintext) || i < len(decrypted); i++ {
					if i >= len(tc.plaintext) {
						t.Logf("Position %d: Original missing, Decrypted: %q", i, decrypted[i])
						break
					}
					if i >= len(decrypted) {
						t.Logf("Position %d: Original: %q, Decrypted missing", i, tc.plaintext[i])
						break
					}
					if tc.plaintext[i] != decrypted[i] {
						t.Logf("Position %d differs: Original: %q (0x%02x), Decrypted: %q (0x%02x)",
							i, tc.plaintext[i], tc.plaintext[i], decrypted[i], decrypted[i])
					}
				}
			}
		})
	}
}

func TestPasswordEdgeCases(t *testing.T) {
	// 测试各种密码的边界情况
	passwords := []struct {
		name     string
		password string
	}{
		{"Empty", ""},
		{"Single char", "a"},
		{"All same char", strings.Repeat("a", 100)},
		{"Very long", strings.Repeat("password", 1000)},
		{"Unicode", "密码🔐"},
		{"Control chars", "pass\x00word"},
		{"Newlines", "pass\nword"},
		{"Special chars", "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"},
		{"Spaces", "pass word with spaces"},
		{"Tabs", "pass\tword"},
		{"Null bytes", "pass\x00word\x00"},
		{"UTF-8 4-byte char", "pass🎯word"},
		{"Mixed encoding", "pass\u202Eword"}, // 右到左覆盖字符
	}

	for _, pw := range passwords {
		t.Run(pw.name, func(t *testing.T) {
			config := encryption.NewPasswordEncryptorConfig()
			config.Password = pw.password
			config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				if pw.password == "" {
					// 空密码应该失败
					return
				}
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			plaintext := "test data"

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
				t.Errorf("Decryption failed for password: %s", pw.name)
			}
		})
	}
}
func TestSaltAndIVEdgeCases(t *testing.T) {
	// 为不同算法创建专用测试

	t.Run("AES-256 Valid Configurations", func(t *testing.T) {
		testAESConfigs(t)
	})

	t.Run("DES Valid Configurations", func(t *testing.T) {
		testDESConfigs(t)
	})
}

func testAESConfigs(t *testing.T) {
	testCases := []struct {
		name string
		salt int
		iv   int
	}{
		{"Default", 16, 0}, // 0表示使用默认IV大小（16）
		{"LargeSalt", 32, 0},
		{"CustomIV", 16, 16},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := encryption.NewPasswordEncryptorConfig()
			config.Password = "test"
			config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()
			config.SaltSize = tc.salt
			config.IVSize = tc.iv

			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			testEncryptionDecryption(t, encryptor, "test data")
		})
	}
}

func testDESConfigs(t *testing.T) {
	testCases := []struct {
		name string
		salt int
		iv   int
	}{
		{"Default", 8, 0}, // 0表示使用默认IV大小（8）
		{"LargeSalt", 16, 0},
		{"CustomIV", 8, 8},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := encryption.NewPasswordEncryptorConfig()
			config.Password = "test"
			config.Algorithm = constants.AlgorithmPBEWithMD5AndDES.String()
			config.SaltSize = tc.salt
			config.IVSize = tc.iv

			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			testEncryptionDecryption(t, encryptor, "test data")
		})
	}
}

func testEncryptionDecryption(t *testing.T, encryptor *encryption.ConfigStringEncryptor, plaintext string) {
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
		t.Errorf("Decryption failed. Got: %q, Want: %q", decrypted, plaintext)
	}
}
