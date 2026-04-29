package algorithm

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"errors"
	"hash"

	"github.com/lysice/gocrypt/constants"
)

// PBEWithMD5AndDES 实现PBEWithMD5AndDES算法
type PBEWithMD5AndDES struct{}

func (a *PBEWithMD5AndDES) Name() string {
	return constants.AlgorithmPBEWithMD5AndDES.String()
}

func (a *PBEWithMD5AndDES) KeySize() int {
	return 8 // DES密钥长度是8字节
}

func (a *PBEWithMD5AndDES) BlockSize() int {
	return 8 // DES块大小是8字节
}

func (a *PBEWithMD5AndDES) IVSize() int {
	return 8 // DES IV大小是8字节
}

func (a *PBEWithMD5AndDES) RequiresIV() bool {
	return true
}

func (a *PBEWithMD5AndDES) GenerateKey(password, salt []byte, iterations int) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	if iterations <= 0 {
		iterations = 1
	}

	// PBKDF1 with MD5
	key := pbkdf1(md5.New, password, salt, iterations, a.KeySize())

	// DES密钥需要奇校验
	for i := 0; i < len(key); i++ {
		parity := byte(0)
		for j := 0; j < 7; j++ {
			if (key[i]>>j)&1 == 1 {
				parity ^= 1
			}
		}
		key[i] = (key[i] & 0xFE) | (parity & 1)
	}

	return key, nil
}

func (a *PBEWithMD5AndDES) CreateEncryptor(key []byte) (cipher.Block, error) {
	if len(key) != a.KeySize() {
		return nil, errors.New("invalid key size")
	}
	return des.NewCipher(key)
}

func (a *PBEWithMD5AndDES) CreateDecryptor(key []byte) (cipher.Block, error) {
	return a.CreateEncryptor(key)
}

func (a *PBEWithMD5AndDES) CreateEncryptMode(block cipher.Block, iv []byte) cipher.BlockMode {
	return cipher.NewCBCEncrypter(block, iv)
}

func (a *PBEWithMD5AndDES) CreateDecryptMode(block cipher.Block, iv []byte) cipher.BlockMode {
	return cipher.NewCBCDecrypter(block, iv)
}

// pbkdf1 PBKDF1实现
func pbkdf1(hashFunc func() hash.Hash, password, salt []byte, iterations, keyLen int) []byte {
	hash := hashFunc()
	hash.Write(password)
	hash.Write(salt)
	digest := hash.Sum(nil)

	for i := 1; i < iterations; i++ {
		hash.Reset()
		hash.Write(digest)
		digest = hash.Sum(nil)
	}

	if len(digest) > keyLen {
		return digest[:keyLen]
	}
	return digest
}
