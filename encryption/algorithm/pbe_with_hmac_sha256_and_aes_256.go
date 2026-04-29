package algorithm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"

	"github.com/lysice/gocrypt/constants"
	"golang.org/x/crypto/pbkdf2"
)

// PBEWithHMACSHA256AndAES256 实现PBEWithHMACSHA256AndAES_256算法
type PBEWithHMACSHA256AndAES256 struct{}

func (a *PBEWithHMACSHA256AndAES256) Name() string {
	return constants.AlgorithmPBEWithHMACSHA256AndAES256.String()
}

func (a *PBEWithHMACSHA256AndAES256) KeySize() int {
	return 32 // AES-256密钥长度
}

func (a *PBEWithHMACSHA256AndAES256) BlockSize() int {
	return aes.BlockSize // 16字节
}

func (a *PBEWithHMACSHA256AndAES256) IVSize() int {
	return aes.BlockSize // 16字节
}

func (a *PBEWithHMACSHA256AndAES256) RequiresIV() bool {
	return true
}

func (a *PBEWithHMACSHA256AndAES256) GenerateKey(password, salt []byte, iterations int) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	if iterations <= 0 {
		iterations = 1000
	}

	// 使用PBKDF2 with HMAC-SHA256
	return pbkdf2.Key(password, salt, iterations, a.KeySize(), sha256.New), nil
}

func (a *PBEWithHMACSHA256AndAES256) CreateEncryptor(key []byte) (cipher.Block, error) {
	if len(key) != a.KeySize() {
		return nil, errors.New("invalid key size")
	}
	return aes.NewCipher(key)
}

func (a *PBEWithHMACSHA256AndAES256) CreateDecryptor(key []byte) (cipher.Block, error) {
	return a.CreateEncryptor(key)
}

func (a *PBEWithHMACSHA256AndAES256) CreateEncryptMode(block cipher.Block, iv []byte) cipher.BlockMode {
	return cipher.NewCBCEncrypter(block, iv)
}

func (a *PBEWithHMACSHA256AndAES256) CreateDecryptMode(block cipher.Block, iv []byte) cipher.BlockMode {
	return cipher.NewCBCDecrypter(block, iv)
}
