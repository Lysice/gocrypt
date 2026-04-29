package salt

import "crypto/rand"

// RandomSaltGenerator 随机Salt生成器
type RandomSaltGenerator struct{}

func (g *RandomSaltGenerator) Name() string {
	return "random"
}

func (g *RandomSaltGenerator) GenerateSalt(size int) ([]byte, error) {
	if size <= 0 {
		size = 8
	}

	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}
