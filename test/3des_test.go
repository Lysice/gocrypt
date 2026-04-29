package test

import (
	"testing"

	"github.com/lysice/gocrypt/constants"
	"github.com/lysice/gocrypt/encryption"
)

func TestTripleDESEncryption(t *testing.T) {
	testCases := []struct {
		name      string
		password  string
		plaintext string
	}{
		{
			name:      "Simple password",
			password:  "my-3des-password-123",
			plaintext: "test-secret-data",
		},
		{
			name:      "Long password",
			password:  "very-long-password-for-3des-algorithm-testing",
			plaintext: "This is a longer test message for 3DES encryption",
		},
		{
			name:      "Short password",
			password:  "short",
			plaintext: "short message",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := encryption.NewPasswordEncryptorConfig()
			config.Password = tc.password
			config.Algorithm = constants.AlgorithmPBEWithSHA1AndDESede.String()
			config.Iterations = 1000
			config.SaltSize = 8
			config.KeyObtentionIterations = 1000

			encryptor, err := encryption.NewConfigStringEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			// Test encryption
			encrypted, err := encryptor.Encrypt(tc.plaintext)
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
		})
	}
}
