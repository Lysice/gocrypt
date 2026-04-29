package salt

// SaltGenerator Salt生成器接口
type SaltGenerator interface {
	// GenerateSalt 生成Salt
	GenerateSalt(size int) ([]byte, error)

	// Name 返回生成器名称
	Name() string
}
