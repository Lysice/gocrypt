package encryption

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/lysice/gocrypt/constants"
	"github.com/lysice/gocrypt/encryption/algorithm"
	"github.com/lysice/gocrypt/encryption/iv"
	"github.com/lysice/gocrypt/encryption/salt"
)

// standardPBEStringEncryptor 标准PBE字符串加密器
type standardPBEStringEncryptor struct {
	config    *passwordEncryptorConfig
	algorithm algorithm.PBEAlgorithm
	saltGen   salt.SaltGenerator
	ivGen     iv.IVGenerator
}

// newStandardPBEStringEncryptor 创建标准PBE加密器
func newStandardPBEStringEncryptor(config *passwordEncryptorConfig) (*standardPBEStringEncryptor, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	// 创建算法
	algo, err := createAlgorithm(config.Algorithm)
	if err != nil {
		return nil, err
	}

	// 创建Salt生成器
	saltGen, err := createSaltGenerator(config.SaltGenerator)
	if err != nil {
		return nil, err
	}

	// 创建IV生成器
	ivGen, err := createIVGenerator(config.IVGenerator)
	if err != nil {
		return nil, err
	}

	return &standardPBEStringEncryptor{
		config:    config,
		algorithm: algo,
		saltGen:   saltGen,
		ivGen:     ivGen,
	}, nil
}

// Encrypt 加密字符串
func (e *standardPBEStringEncryptor) Encrypt(message string) (string, error) {
	if len(message) == 0 {
		return "", errors.New("message cannot be empty")
	}

	// 生成Salt
	saltBytes, err := e.saltGen.GenerateSalt(e.config.SaltSize)
	if err != nil {
		return "", err
	}

	// 生成密钥
	key, err := e.algorithm.GenerateKey([]byte(e.config.Password), saltBytes, e.config.KeyObtentionIterations)
	if err != nil {
		return "", err
	}

	// 生成IV（如果需要）
	var ivBytes []byte
	if e.algorithm.RequiresIV() {
		ivSize := e.config.IVSize
		if ivSize <= 0 {
			ivSize = e.algorithm.IVSize()
		}
		ivBytes, err = e.ivGen.GenerateIV(ivSize)
		if err != nil {
			return "", err
		}
	}

	// 创建加密器
	block, err := e.algorithm.CreateEncryptor(key)
	if err != nil {
		return "", err
	}

	// 填充明文
	paddedMessage := pkcs5Padding([]byte(message), e.algorithm.BlockSize())

	// 加密
	ciphertext := make([]byte, len(paddedMessage))
	if e.algorithm.RequiresIV() {
		blockMode := e.algorithm.CreateEncryptMode(block, ivBytes)
		blockMode.CryptBlocks(ciphertext, paddedMessage)
	} else {
		// ECB模式（不推荐，仅用于兼容）
		for i := 0; i < len(paddedMessage); i += e.algorithm.BlockSize() {
			block.Encrypt(ciphertext[i:], paddedMessage[i:])
		}
	}

	// 组合结果
	var result []byte
	if e.algorithm.RequiresIV() {
		result = make([]byte, len(saltBytes)+len(ivBytes)+len(ciphertext))
		copy(result, saltBytes)
		copy(result[len(saltBytes):], ivBytes)
		copy(result[len(saltBytes)+len(ivBytes):], ciphertext)
	} else {
		result = make([]byte, len(saltBytes)+len(ciphertext))
		copy(result, saltBytes)
		copy(result[len(saltBytes):], ciphertext)
	}

	// 编码输出
	return encodeOutput(result, e.config.StringOutputType), nil
}

// Decrypt 解密字符串
func (e *standardPBEStringEncryptor) Decrypt(encryptedMessage string) (string, error) {
	if len(encryptedMessage) == 0 {
		return "", errors.New("encrypted message cannot be empty")
	}

	// 解码输入
	data, err := decodeInput(encryptedMessage, e.config.StringOutputType)
	if err != nil {
		return "", err
	}

	// 提取Salt
	if len(data) < e.config.SaltSize {
		return "", errors.New("invalid encrypted data: too short for salt")
	}
	saltBytes := data[:e.config.SaltSize]
	data = data[e.config.SaltSize:]

	// 提取IV（如果需要）
	var ivBytes []byte
	if e.algorithm.RequiresIV() {
		ivSize := e.config.IVSize
		if ivSize <= 0 {
			ivSize = e.algorithm.IVSize()
		}
		if len(data) < ivSize {
			return "", errors.New("invalid encrypted data: too short for IV")
		}
		ivBytes = data[:ivSize]
		data = data[ivSize:]
	}

	ciphertext := data

	// 生成密钥
	key, err := e.algorithm.GenerateKey([]byte(e.config.Password), saltBytes, e.config.KeyObtentionIterations)
	if err != nil {
		return "", err
	}

	// 创建解密器
	block, err := e.algorithm.CreateDecryptor(key)
	if err != nil {
		return "", err
	}

	// 解密
	plaintext := make([]byte, len(ciphertext))
	if e.algorithm.RequiresIV() {
		blockMode := e.algorithm.CreateDecryptMode(block, ivBytes)
		blockMode.CryptBlocks(plaintext, ciphertext)
	} else {
		// ECB模式
		for i := 0; i < len(ciphertext); i += e.algorithm.BlockSize() {
			block.Decrypt(plaintext[i:], ciphertext[i:])
		}
	}

	// 去除填充
	plaintext, err = pkcs5Unpadding(plaintext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// 辅助函数
func validateConfig(config *passwordEncryptorConfig) error {
	if config.Password == "" {
		return errors.New("password cannot be empty")
	}
	if config.SaltSize <= 0 {
		return errors.New("salt size must be positive")
	}
	if config.KeyObtentionIterations <= 0 {
		return errors.New("KeyObtentionIterations must be positive")
	}

	return nil
}

func createAlgorithm(algoName string) (algorithm.PBEAlgorithm, error) {
	var algo256 = strings.ToUpper(constants.AlgorithmPBEWithHMACSHA256AndAES256.String())
	var algosede = strings.ToUpper(constants.AlgorithmPBEWithSHA1AndDESede.String())
	var algodes = strings.ToUpper(constants.AlgorithmPBEWithMD5AndDES.String())
	switch strings.ToUpper(algoName) {
	case algodes:
		return &algorithm.PBEWithMD5AndDES{}, nil
	case algosede:
		return &algorithm.PBEWithSHA1AndDESede{}, nil
	case algo256:
		return &algorithm.PBEWithHMACSHA256AndAES256{}, nil
	default:
		return nil, errors.New("unsupported algorithm: " + algoName)
	}
}

func createSaltGenerator(genName string) (salt.SaltGenerator, error) {
	switch strings.ToLower(genName) {
	case "random":
		return &salt.RandomSaltGenerator{}, nil
	default:
		return nil, errors.New("unsupported salt generator: " + genName)
	}
}

func createIVGenerator(genName string) (iv.IVGenerator, error) {
	switch strings.ToLower(genName) {
	case "random":
		return &iv.RandomIVGenerator{}, nil
	default:
		return nil, errors.New("unsupported IV generator: " + genName)
	}
}

func encodeOutput(data []byte, outputType string) string {
	switch strings.ToLower(outputType) {
	case constants.OutputTypeHex.String():
		return hex.EncodeToString(data)
	case constants.OutputTypeBase64.String():
		return base64.StdEncoding.EncodeToString(data)
	default:
		return base64.StdEncoding.EncodeToString(data)
	}
}

func decodeInput(data, inputType string) ([]byte, error) {
	switch strings.ToLower(inputType) {
	case constants.OutputTypeHex.String():
		return hex.DecodeString(data)
	case constants.OutputTypeBase64.String():
		return base64.StdEncoding.DecodeString(data)
	default:
		return base64.StdEncoding.DecodeString(data)
	}
}
