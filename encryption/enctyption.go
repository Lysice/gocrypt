// Package encryption provides Jasypt-compatible encryption for Go applications.
//
// Gocrypt is a pure Go implementation of the popular Java Jasypt library,
// providing simplified encryption for configuration values and sensitive data.
// It's designed to be API-compatible with Jasypt, making it easy to migrate
// from Java to Go or use both in the same ecosystem.
//
// Features:
//   - Complete compatibility with Jasypt encrypted values
//   - Support for multiple PBE algorithms
//   - ENC() wrapper for configuration values
//   - Simple and intuitive API
//   - Zero dependencies (except standard library)
//   - Thread-safe implementation
//
// Basic Usage:
//
//	config := NewPasswordEncryptorConfig()
//	config.Password = "my-secret-key"
//	config.Algorithm = "PBEWithHMACSHA256AndAES_256"
//	encryptor, err := NewConfigStringEncryptor(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Encrypt a value
//	encrypted, _ := encryptor.Encrypt("my-password")
//	// Returns: "ENC(encrypted-string)"
//
//	// Decrypt a value
//	decrypted, _ := encryptor.Decrypt("ENC(encrypted-string)")
//
// Algorithms:
//   - PBEWithMD5AndDES
//   - PBEWithSHA1AndDESede
//   - PBEWithHMACSHA256AndAES_256
//
// For more examples, see the examples directory.
package encryption

// 导出公共类型
type (
	// PasswordEncryptorConfig 配置加密器
	PasswordEncryptorConfig = passwordEncryptorConfig

	// ConfigStringEncryptor 配置字符串加密器
	ConfigStringEncryptor = configStringEncryptor

	// StringEncryptor 字符串加密器接口
	StringEncryptor interface {
		Encrypt(message string) (string, error)
		Decrypt(encryptedMessage string) (string, error)
	}
)

// 导出公共函数
var (
	// NewPasswordEncryptorConfig 创建新的密码加密器配置
	NewPasswordEncryptorConfig = newPasswordEncryptorConfig

	// NewConfigStringEncryptor 创建配置字符串加密器
	NewConfigStringEncryptor = newConfigStringEncryptor

	// NewStandardPBEStringEncryptor 创建标准PBE字符串加密器
	NewStandardPBEStringEncryptor = newStandardPBEStringEncryptor

	// IsEncrypted 检查字符串是否已被加密
	IsEncrypted = isEncrypted

	// WrapWithENC 用ENC()包装值
	WrapWithENC = wrapWithENC

	// ExtractEncryptedValue 从ENC()包装中提取加密值
	ExtractEncryptedValue = extractEncryptedValue
)
