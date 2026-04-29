# Gocrypt
https://pkg.go.dev/badge/github.com/lysice/gocrypt.svg
https://goreportcard.com/badge/github.com/lysice/gocrypt
https://img.shields.io/badge/license-MIT-blue.svg
https://img.shields.io/github/v/release/lysice/gocrypt
A pure Go implementation of the popular Java Jasypt library for simplified encryption of configuration values and sensitive data.

## Features
Complete Jasypt Compatibility: Fully compatible with Java Jasypt encrypted values
Multiple Algorithms: Supports PBEWithMD5AndDES, PBEWithSHA1AndDESede, PBEWithHMACSHA256AndAES_256
- Simple API: Easy-to-use encryption/decryption interface
- Configuration Support: Built-in ENC() wrapper for configuration files
- Zero Dependencies: Minimal dependencies for security and simplicity
- Comprehensive Tests: Thorough test coverage
- CLI Tool: Command-line interface for easy use
- Type-Safe: Constants for algorithms and configuration options
## Installation
```
go get github.com/lysice/gocrypt
```

## Quick Start
```
package gosypt

import (
	"fmt"
	"log"

	"github.com/lysice/gocrypt/encryption"
)

package main
import (
	"fmt"
	"log"
	"github.com/lysice/gocrypt/encryption"
)
func main() {
	// Create configuration
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "my-secret-password"
	config.Algorithm = encryption.AlgorithmPBEWithHMACSHA256AndAES256.String()
	// Create encryptor
	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt a value
	plaintext := "my-database-password-123"
	encrypted, err := encryptor.Encrypt(plaintext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Encrypted: %s\n", encrypted)
	// Output: ENC(base64-encrypted-string)

	// Decrypt a value
	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted: %s\n", decrypted)
	// Output: my-database-password-123

	// Check if a value is encrypted
	if encryption.IsEncrypted(encrypted) {
		fmt.Println("Value is encrypted")
	}
}

```
## Documentation
Full documentation is available at https://pkg.go.dev/github.com/lysice/gosypt .

### Supported Algorithms


| Algorithm  |  Key Size | Security  | Notes  |
|---|---|---|---|
|  PBEWithMD5AndDES | 56-bit  | Weak  | Legacy support only  |
|  PBEWithSHA1AndDESede |  112/168-bit | Moderate  |Triple DES   |
|PBEWithHMACSHA256AndAES_256|256-bit|Strong|Recommended|



### Usage
#### 1.Basic Encryption/Decryption
```go
package main

import (
	"fmt"
	"github.com/lysice/gocrypt/encryption"
	"log"
)

func main() {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "my-secret-key"
	config.Algorithm = encryption.AlgorithmPBEWithHMACSHA256AndAES256.String()
	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt
	encrypted, err := encryptor.Encrypt("sensitive-data")
	if err != nil {
		log.Fatal(err)
	}

	// Output: ENC(base64-string)
	fmt.Println(encrypted)

	// Decrypt
	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(decrypted) // Output: sensitive-data
}

```


## Configuration File Support
```go
package main

import (
	"fmt"
	"github.com/lysice/gocrypt/encryption"
	"log"
)

func main() {
	config := encryption.NewPasswordEncryptorConfig()
	config.Password = "config-secret"
	encryptor, err := encryption.NewConfigStringEncryptor(config)
	if err != nil {
		log.Fatal(err)
	}

	// Simulated configuration values
	encryptedValues := map[string]string{
		"db.password": "ENC(encrypted-string-here)",
		"api.key":     "ENC(another-encrypted-string)",
	}

	// Decrypt configuration
	for key, value := range encryptedValues {
		decrypted, err := encryptor.Decrypt(value)
		if err != nil {
			log.Printf("Failed to decrypt %s: %v", key, err)
			continue
		}
		fmt.Printf("%s = %s\n", key, decrypted)
	}
}
```

## Configuration Options
```
config := encryption.NewPasswordEncryptorConfig()
// Required
config.Password = "your-secret-key" // Encryption password
// Algorithm (default: PBEWithHMACSHA256AndAES_256)
config.Algorithm = encryption.AlgorithmPBEWithHMACSHA256AndAES256.String()
// or
config.Algorithm = encryption.AlgorithmPBEWithMD5AndDES.String()
// or
config.Algorithm = encryption.AlgorithmPBEWithSHA1AndDESede.String()
// Optional
config.Iterations = 1000 // Key derivation iterations
config.SaltSize = 16 // Salt size in bytes
config.StringOutputType = "base64" // Output type: "base64" or "hex"
config.Prefix = "ENC(" // Custom prefix
config.Suffix = ")" // Custom suffix
```


## Command Line Interface
### 1.Installation
```
go install github.com/lysice/gocrypt/cmd/gocrypt-cli@latest
```
### 2.Usage
#### 2.1 Encrypt a value
```
gocrypt-cli -action encrypt -password "my-secret" -value "sensitive-data"
```

#### 2.2 Decrypt a value
```
gocrypt-cli -action decrypt -password "my-secret" -value "ENC(encrypted-string)"
```

#### 2.3 With custom algorithm
```
gocrypt-cli -action encrypt -algorithm PBEWithMD5AndDES -password "test" -value "data"
```

#### 2.4 With hex output
```
gocrypt-cli -action encrypt -output-type hex -password "test" -value "data"
```

#### 2.5 CLI Options
```
Usage:
gocrypt-cli [options]
Options:
1.-password string
        Encryption password (required)
2.-algorithm string
Encryption algorithm. Options: PBEWithMD5AndDES, PBEWithSHA1AndDESede, PBEWithHMACSHA256AndAES_256 (default "PBEWithHMACSHA256AndAES_256")

3.-iterations int
Key obtention iterations (default 1000)

4.-action string
Action: encrypt or decrypt (required)

5.-value string
Value to encrypt/decrypt (required)

6.-salt-size int
Salt size in bytes (default 16)

7.-output-type string
Output type: base64 or hex (default "base64")
```

## Migration from Java Jasypt
Gocrypt is designed to be fully compatible with Java Jasypt:
Same encrypted values: Values encrypted with Java Jasypt can be decrypted with Gocrypt
Same algorithms: Supported algorithms: PBEWithMD5AndDES, PBEWithSHA1AndDESede, PBEWithHMACSHA256AndAES_256
Same configuration: Use the same password and algorithm settings

## Security Considerations
- Use Strong Passwords:   Always use strong, random passwords for encryption
- Key Management: Store encryption passwords securely (e.g., environment variables, secrets manager)
- Algorithm Choice: Prefer PBEWithHMACSHA256AndAES_256 for new implementations
- Iterations: Use at least 100,000 iterations for PBKDF2 in production
- Salt Size: Use at least 16 bytes of salt

## Examples
See the examples directory for more usage examples:

- Basic Example: Basic encryption/decryption
- Configuration Example: Encrypting configuration values

## Testing
Run all tests
```
go test ./...

### Run specific tests
go test ./test -run TestEncryptionDecryption
go test ./test -run TestAlgorithmCompatibility
go test ./test -run TestEdgeCases
...

### Run with verbose output
go test ./test -v
Run benchmarks
go test ./test -bench=. -benchtime=3s
```

## Contributing
Contributions are welcome! 
> Please read the Contributing Guidelines.
- Fork the repository
- Create a feature branch
- Make your changes
- Run tests
- Commit your changes
- Push to your fork
- Create a Pull Request


## License
> This project is licensed under the MIT License 
> see the LICENSE file for details.

## Acknowledgments
> Inspired by the Java Jasypt library
> Thanks to all contributors and users.