#!/bin/bash

# 运行所有测试
echo "Running all tests..."
echo "==================="

# 基本功能测试
echo ""
echo "1. Running basic encryption tests..."
go test ./test -run TestEncryptionDecryption -v

echo ""
echo "2. Running algorithm tests..."
go test ./test -run TestAlgorithmCompatibility -v

echo ""
echo "3. Running configuration tests..."
go test ./test -run TestConfigStringEncryptor -v

echo ""
echo "4. Running integration tests..."
go test ./test -run TestMultipleEncryptorsSamePassword -v
go test ./test -run TestConcurrentEncryption -v

echo ""
echo "5. Running edge case tests..."
go test ./test -run TestEdgeCases -v

echo ""
echo "6. Running compatibility tests..."
go test ./test -run TestCompatibilityWithJavaJasypt -v

echo ""
echo "7. Running performance tests..."
go test ./test -run TestPerformanceCharacteristics -v
go test ./test -run TestIterationsPerformance -v

# 运行基准测试
echo ""
echo "8. Running benchmarks..."
go test ./test -bench=. -benchtime=3s

echo ""
echo "All tests completed!"