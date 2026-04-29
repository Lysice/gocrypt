package encryption

import (
	"strings"
)

// configStringEncryptor 配置字符串加密器
type configStringEncryptor struct {
	encryptor StringEncryptor
	prefix    string
	suffix    string
}

// newConfigStringEncryptor 创建配置字符串加密器
func newConfigStringEncryptor(config *passwordEncryptorConfig) (*configStringEncryptor, error) {
	encryptor, err := newStandardPBEStringEncryptor(config)
	if err != nil {
		return nil, err
	}

	prefix := config.Prefix
	if prefix == "" {
		prefix = "ENC("
	}

	suffix := config.Suffix
	if suffix == "" {
		suffix = ")"
	}

	return &configStringEncryptor{
		encryptor: encryptor,
		prefix:    prefix,
		suffix:    suffix,
	}, nil
}

// Encrypt 加密并包装
func (c *configStringEncryptor) Encrypt(message string) (string, error) {
	encrypted, err := c.encryptor.Encrypt(message)
	if err != nil {
		return "", err
	}
	return c.prefix + encrypted + c.suffix, nil
}

// Decrypt 解密（自动处理ENC包装）
func (c *configStringEncryptor) Decrypt(encryptedValue string) (string, error) {
	if !c.IsEncrypted(encryptedValue) {
		return encryptedValue, nil
	}

	// 提取内部加密值
	inner := strings.TrimPrefix(encryptedValue, c.prefix)
	inner = strings.TrimSuffix(inner, c.suffix)

	return c.encryptor.Decrypt(inner)
}

// isEncrypted 检查是否已被加密
func (c *configStringEncryptor) IsEncrypted(value string) bool {
	return strings.HasPrefix(value, c.prefix) && strings.HasSuffix(value, c.suffix)
}

// wrapWithENC 用ENC()包装
func wrapWithENC(value string) string {
	return "ENC(" + value + ")"
}

func isEncrypted(value string) bool {
	return strings.HasPrefix(value, "ENC(") && strings.HasSuffix(value, ")")
}
func checkIfEncrypted(value string, prefix, suffix string) bool {
	return strings.HasPrefix(value, prefix) && strings.HasSuffix(value, suffix)
}

// extractEncryptedValue 从ENC()中提取值
func extractEncryptedValue(value string) (string, error) {
	if !checkIfEncrypted(value, "ENC(", ")") {
		return value, nil
	}
	inner := strings.TrimPrefix(value, "ENC(")
	inner = strings.TrimSuffix(inner, ")")
	return inner, nil
}
