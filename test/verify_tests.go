package test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestAll(t *testing.T) {
	fmt.Println("Verifying Gocrypt Tests")
	fmt.Println("========================")

	tests := []struct {
		name string
		cmd  string
	}{
		{"Basic Functionality", "go test ./test -run TestEncryptionDecryption -v"},
		{"Algorithm Support", "go test ./test -run TestAlgorithmCompatibility -v"},
		{"Configuration", "go test ./test -run TestConfigStringEncryptor -v"},
		{"Integration", "go test ./test -run TestMultipleEncryptorsSamePassword -v"},
		{"Concurrency", "go test ./test -run TestConcurrentEncryption -v"},
		{"Edge Cases", "go test ./test -run TestEdgeCases -v"},
		{"Compatibility", "go test ./test -run TestCompatibilityWithJavaJasypt -v"},
	}

	allPassed := true

	for _, test := range tests {
		fmt.Printf("\nRunning: %s\n", test.name)
		fmt.Println(strings.Repeat("-", len(test.name)+9))

		cmd := exec.Command("sh", "-c", test.cmd)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Printf("❌ %s FAILED\n", test.name)
			allPassed = false
		} else {
			fmt.Printf("✅ %s PASSED\n", test.name)
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 30))
	if allPassed {
		fmt.Println("✅ All tests PASSED!")
		os.Exit(0)
	} else {
		fmt.Println("❌ Some tests FAILED!")
		os.Exit(1)
	}
}
