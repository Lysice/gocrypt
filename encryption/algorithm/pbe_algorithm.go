package algorithm

import (
	"crypto/cipher"
)

// PBEAlgorithm PBE算法接口
type PBEAlgorithm interface {
	// Name 返回算法名称
	Name() string

	// KeySize 返回密钥大小（字节）
	KeySize() int

	// BlockSize 返回块大小（字节）
	BlockSize() int

	// IVSize 返回IV大小（字节）
	IVSize() int

	// RequiresIV 是否需要IV
	RequiresIV() bool

	// GenerateKey 生成密钥
	GenerateKey(password, salt []byte, iterations int) ([]byte, error)

	// CreateEncryptor 创建加密器
	CreateEncryptor(key []byte) (cipher.Block, error)

	// CreateDecryptor 创建解密器
	CreateDecryptor(key []byte) (cipher.Block, error)

	// CreateEncryptMode 创建加密模式
	CreateEncryptMode(block cipher.Block, iv []byte) cipher.BlockMode

	// CreateDecryptMode 创建解密模式
	CreateDecryptMode(block cipher.Block, iv []byte) cipher.BlockMode
}
