package algorithm

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"errors"

	"github.com/lysice/gocrypt/constants"
	"golang.org/x/crypto/pbkdf2"
)

// PBEWithSHA1AndDESede 实现PBEWithSHA1AndDESede算法（Triple DES）
type PBEWithSHA1AndDESede struct{}

func (a *PBEWithSHA1AndDESede) Name() string {
	return constants.AlgorithmPBEWithSHA1AndDESede.String()
}

func (a *PBEWithSHA1AndDESede) KeySize() int {
	return 24 // 3DES密钥长度，可以是16或24字节
}

func (a *PBEWithSHA1AndDESede) BlockSize() int {
	return des.BlockSize // 8字节
}

func (a *PBEWithSHA1AndDESede) IVSize() int {
	return des.BlockSize // 8字节
}

func (a *PBEWithSHA1AndDESede) RequiresIV() bool {
	return true
}

func (a *PBEWithSHA1AndDESede) GenerateKey(password, salt []byte, iterations int) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	if iterations <= 0 {
		iterations = 1000
	}

	// 使用PBKDF2 with SHA1生成24字节密钥
	key := pbkdf2.Key(password, salt, iterations, a.KeySize(), sha1.New)

	// 3DES密钥需要奇校验
	for i := 0; i < len(key); i++ {
		// 设置DES奇偶校验位
		parity := byte(0)
		for j := 0; j < 7; j++ {
			if (key[i]>>j)&1 == 1 {
				parity ^= 1
			}
		}
		// 设置第8位为奇偶校验位
		if parity == 1 {
			key[i] |= 0x01
		} else {
			key[i] &= 0xFE
		}
	}

	return key, nil
}

func (a *PBEWithSHA1AndDESede) CreateEncryptor(key []byte) (cipher.Block, error) {
	if len(key) != 16 && len(key) != 24 {
		return nil, errors.New("invalid key size for 3DES, must be 16 or 24 bytes")
	}
	return des.NewTripleDESCipher(key)
}

func (a *PBEWithSHA1AndDESede) CreateDecryptor(key []byte) (cipher.Block, error) {
	return a.CreateEncryptor(key)
}

func (a *PBEWithSHA1AndDESede) CreateEncryptMode(block cipher.Block, iv []byte) cipher.BlockMode {
	return cipher.NewCBCEncrypter(block, iv)
}

func (a *PBEWithSHA1AndDESede) CreateDecryptMode(block cipher.Block, iv []byte) cipher.BlockMode {
	return cipher.NewCBCDecrypter(block, iv)
}
