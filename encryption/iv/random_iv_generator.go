package iv

import (
	"crypto/rand"
	"errors"
)

// RandomIVGenerator 随机IV生成器
type RandomIVGenerator struct{}

func (g *RandomIVGenerator) Name() string {
	return "RandomIVGenerator"
}

func (g *RandomIVGenerator) GenerateIV(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("invalid IV size")
	}

	iv := make([]byte, size)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return iv, nil
}
