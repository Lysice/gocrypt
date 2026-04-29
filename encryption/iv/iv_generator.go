package iv

// IVGenerator IV生成器接口
type IVGenerator interface {
	// GenerateIV 生成IV
	GenerateIV(size int) ([]byte, error)

	// Name 返回生成器名称
	Name() string
}
