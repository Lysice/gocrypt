package test

import (
	"strings"
	"testing"
	"time"

	"github.com/lysice/gocrypt/constants"
	"github.com/lysice/gocrypt/encryption"
)

func BenchmarkEncryption(b *testing.B) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "benchmark-password"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		b.Fatalf("Failed to create encryptor: %v", err)
	}

	testData := []struct {
		name string
		data string
	}{
		{"Empty", ""},
		{"Short", "password"},
		{"Medium", "this-is-a-medium-length-password-for-testing"},
		{"Long", strings.Repeat("A", 1024)},        // 1KB
		{"VeryLong", strings.Repeat("B", 1024*10)}, // 10KB
	}

	for _, td := range testData {
		b.Run(td.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := encryptor.Encrypt(td.data)
				if err != nil {
					b.Fatalf("Encryption failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkDecryption(b *testing.B) {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "benchmark-password"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		b.Fatalf("Failed to create encryptor: %v", err)
	}

	// 预先加密数据
	testData := []struct {
		name      string
		plaintext string
	}{
		{"Empty", ""},
		{"Short", "password"},
		{"Medium", "this-is-a-medium-length-password-for-testing"},
		{"Long", strings.Repeat("A", 1024)},
	}

	encryptedData := make([]string, len(testData))
	for i, td := range testData {
		encrypted, err := encryptor.Encrypt(td.plaintext)
		if err != nil {
			b.Fatalf("Failed to prepare encrypted data: %v", err)
		}
		encryptedData[i] = encrypted
	}

	for i, td := range testData {
		b.Run(td.name, func(b *testing.B) {
			encrypted := encryptedData[i]
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				_, err := encryptor.Decrypt(encrypted)
				if err != nil {
					b.Fatalf("Decryption failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkDifferentAlgorithms(b *testing.B) {
	algorithms := []struct {
		name      string
		algorithm string
	}{
		{constants.AlgorithmPBEWithMD5AndDES.String(),
			constants.AlgorithmPBEWithMD5AndDES.String(),
		},
		{
			constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
			constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
		},
	}

	for _, algo := range algorithms {
		b.Run(algo.name, func(b *testing.B) {
			config := encryption.NewPasswordEncryptorConfig()
			config.Password = "benchmark"
			config.Algorithm = algo.algorithm

			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				b.Fatalf("Failed to create encryptor: %v", err)
			}

			plaintext := "benchmark test data"

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				encrypted, err := encryptor.Encrypt(plaintext)
				if err != nil {
					b.Fatalf("Encryption failed: %v", err)
				}

				_, err = encryptor.Decrypt(encrypted)
				if err != nil {
					b.Fatalf("Decryption failed: %v", err)
				}
			}
		})
	}
}

func TestPerformanceCharacteristics(t *testing.T) {
	// 这不是标准的benchmark，而是性能特征测试
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "performance-test"
	config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()

	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// 测试不同数据大小的性能
	dataSizes := []int{1, 10, 100, 1000, 10000}

	for _, size := range dataSizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			data := strings.Repeat("X", size)

			// 测量加密时间
			start := time.Now()
			encrypted, err := encryptor.Encrypt(data)
			encryptTime := time.Since(start)

			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// 测量解密时间
			start = time.Now()
			decrypted, err := encryptor.Decrypt(encrypted)
			decryptTime := time.Since(start)

			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decrypted != data {
				t.Errorf("Data mismatch for size %d", size)
			}

			t.Logf("Size: %d bytes, Encrypt: %v, Decrypt: %v, Total: %v",
				size, encryptTime, decryptTime, encryptTime+decryptTime)

			// 验证加密输出大小
			inner := strings.TrimPrefix(encrypted, "ENC(")
			inner = strings.TrimSuffix(inner, ")")

			// Base64编码会增加大约33%的大小
			// 加上salt和IV，实际加密数据会比明文大
			encryptedSize := len(inner)
			t.Logf("Encrypted size: %d bytes (%.2fx original)",
				encryptedSize, float64(encryptedSize)/float64(size))
		})
	}
}

func TestIterationsPerformance(t *testing.T) {
	// 测试不同迭代次数对性能的影响
	iterations := []int{1, 10, 100, 1000, 10000, 100000}

	for _, iter := range iterations {
		t.Run(string(rune(iter)), func(t *testing.T) {
			config := encryption.NewPasswordEncryptorConfig()
			config.Password = "iterations-test"
			config.Algorithm = constants.AlgorithmPBEWithHMACSHA256AndAES256.String()
			config.KeyObtentionIterations = iter

			start := time.Now()
			encryptor, err := encryption.NewConfigStringEncryptor(config)
			createTime := time.Since(start)

			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			// 执行加密操作
			plaintext := "test data"

			start = time.Now()
			encrypted, err := encryptor.Encrypt(plaintext)
			encryptTime := time.Since(start)

			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// 执行解密操作
			start = time.Now()
			decrypted, err := encryptor.Decrypt(encrypted)
			decryptTime := time.Since(start)

			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if decrypted != plaintext {
				t.Errorf("Data mismatch for iterations %d", iter)
			}

			t.Logf("Iterations: %d, Create: %v, Encrypt: %v, Decrypt: %v, Total: %v",
				iter, createTime, encryptTime, decryptTime,
				createTime+encryptTime+decryptTime)
		})
	}
}
