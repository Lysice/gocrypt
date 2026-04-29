package constants

// Algorithm 加密算法常量
type Algorithm string

const (
	// AlgorithmPBEWithMD5AndDES PBE with MD5 and DES算法
	AlgorithmPBEWithMD5AndDES Algorithm = "PBEWithMD5AndDES"

	// AlgorithmPBEWithSHA1AndDESede PBE with SHA1 and 3DES算法
	AlgorithmPBEWithSHA1AndDESede Algorithm = "PBEWithSHA1AndDESede"

	// AlgorithmPBEWithHMACSHA256AndAES256 PBE with HMAC SHA256 and AES-256算法
	AlgorithmPBEWithHMACSHA256AndAES256 Algorithm = "PBEWithHMACSHA256AndAES_256"
)

// String 返回算法字符串表示
func (a Algorithm) String() string {
	return string(a)
}

// OutputType 输出类型常量
type OutputType string

const (
	// OutputTypeBase64 Base64输出格式
	OutputTypeBase64 OutputType = "base64"

	// OutputTypeHex Hex输出格式
	OutputTypeHex OutputType = "hex"
)

// String 返回输出类型字符串表示
func (ot OutputType) String() string {
	return string(ot)
}

// IVGeneratorType IV生成器类型常量
type IVGeneratorType string

const (
	// IVGeneratorRandom 随机IV生成器
	IVGeneratorRandom IVGeneratorType = "random"
)

// String 返回IV生成器类型字符串表示
func (igt IVGeneratorType) String() string {
	return string(igt)
}

// SaltGeneratorType Salt生成器类型常量
type SaltGeneratorType string

const (
	// SaltGeneratorRandom 随机Salt生成器
	SaltGeneratorRandom SaltGeneratorType = "random"
)

// String 返回Salt生成器类型字符串表示
func (sgt SaltGeneratorType) String() string {
	return string(sgt)
}

// Default constants
const (
	// DefaultAlgorithm 默认加密算法
	DefaultAlgorithm = AlgorithmPBEWithHMACSHA256AndAES256

	// DefaultPasswordIterations 默认密码迭代次数
	DefaultPasswordIterations = 1000

	// DefaultSaltSize 默认Salt大小
	DefaultSaltSize = 16

	// DefaultIVSize 0表示使用算法默认
	DefaultIVSize = 0

	// DefaultOutputType 默认输出类型
	DefaultOutputType = OutputTypeBase64

	// DefaultIVGenerator 默认IV生成器
	DefaultIVGenerator = IVGeneratorRandom

	// DefaultSaltGenerator 默认Salt生成器
	DefaultSaltGenerator = SaltGeneratorRandom

	// DefaultPrefix 默认前缀
	DefaultPrefix = "ENC("

	// DefaultSuffix 默认后缀
	DefaultSuffix = ")"
)
