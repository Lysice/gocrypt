package encryption

import (
	"bytes"
	"errors"
)

// pkcs5Padding PKCS5填充
func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// pkcs5Unpadding 去除PKCS5填充
func pkcs5Unpadding(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, errors.New("empty src")
	}

	unpadding := int(src[length-1])
	if unpadding > length || unpadding == 0 {
		return nil, errors.New("invalid padding")
	}

	// 验证填充
	for i := length - unpadding; i < length; i++ {
		if int(src[i]) != unpadding {
			return nil, errors.New("invalid padding")
		}
	}

	return src[:length-unpadding], nil
}
