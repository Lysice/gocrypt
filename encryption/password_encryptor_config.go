package encryption

import "github.com/lysice/gocrypt/constants"

// PasswordEncryptorConfig 密码加密器配置
type passwordEncryptorConfig struct {
	// Algorithm 加密算法
	// 支持: PBEWithMD5AndDES, PBEWithSHA1AndDESede, PBEWithHMACSHA256AndAES_256
	Algorithm string

	// Password 加密密码（主密钥）
	Password string

	// Iterations 密钥派生迭代次数
	Iterations int

	// SaltGenerator Salt生成器名称
	SaltGenerator string

	// SaltSize Salt大小（字节）
	SaltSize int

	// IVGenerator IV生成器名称
	IVGenerator string

	// IVSize IV大小（字节，0表示使用算法默认值）
	IVSize int

	// ProviderName 提供者名称（兼容Jasypt，未使用）
	ProviderName string

	// KeyObtentionIterations 密钥获取迭代次数
	KeyObtentionIterations int

	// StringOutputType 输出类型：base64, hex
	StringOutputType string

	// Prefix 加密字符串前缀
	Prefix string

	// Suffix 加密字符串后缀
	Suffix string
}

// newPasswordEncryptorConfig 创建默认配置
func newPasswordEncryptorConfig() *PasswordEncryptorConfig {
	return &PasswordEncryptorConfig{
		Algorithm:              constants.AlgorithmPBEWithHMACSHA256AndAES256.String(),
		Iterations:             1000,
		SaltGenerator:          "random",
		SaltSize:               16,
		IVGenerator:            "random",
		IVSize:                 0, // 使用算法默认
		ProviderName:           "JasyptGo",
		KeyObtentionIterations: 1000,
		StringOutputType:       constants.OutputTypeBase64.String(),
		Prefix:                 "ENC(",
		Suffix:                 ")",
	}
}
