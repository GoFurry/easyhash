// Package easyhash provides secure password hashing utilities with multiple algorithms
// including PBKDF2, Argon2, scrypt, and bcrypt. Each algorithm includes configurable
// parameters and uses a global salt for additional security.

package easyhash

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// DefaultSalt is a global salt used across all hashing algorithms for additional security
const DefaultSalt = "AwesomeGolangCrypto"

// ====================== MD5 ======================

// CreateMD5 creates an MD5 hash of the input string.
// WARNING: MD5 is cryptographically broken and should not be used for password hashing.
// This function is provided for legacy compatibility only.
func CreateMD5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

// ====================== PBKDF2 ======================

// PBKDF2 configuration struct for PBKDF2 password hashing
type PBKDF2 struct {
	PBKDF2Iterations int // Number of iterations for key derivation
	PBKDF2KeyLength  int // Length of the derived key in bytes
	SaltLength       int // Length of the random salt in bytes
}

// DefaultPBKDF2 returns a PBKDF2 configuration with secure default values
func DefaultPBKDF2() PBKDF2 {
	return PBKDF2{
		PBKDF2Iterations: 100000, // OWASP recommended minimum
		PBKDF2KeyLength:  32,     // 256 bits
		SaltLength:       16,     // 128 bits
	}
}

// CreatePBKDF2 generates a PBKDF2 hash for the given password using the provided configuration.
// Returns a base64-encoded string in format: salt:iterations:hash
func CreatePBKDF2(cfg PBKDF2, password string) (string, error) {
	salt := make([]byte, cfg.SaltLength)
	n, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate random salt: %w", err)
	}
	if n != cfg.SaltLength {
		return "", errors.New("insufficient salt length generated")
	}

	globalSalt := DefaultSalt
	passwordWithGlobalSalt := password + globalSalt

	hash := pbkdf2.Key(
		[]byte(passwordWithGlobalSalt),
		salt,
		cfg.PBKDF2Iterations,
		cfg.PBKDF2KeyLength,
		sha256.New,
	)

	saltBase64 := base64.StdEncoding.EncodeToString(salt)
	hashBase64 := base64.StdEncoding.EncodeToString(hash)
	storedStr := fmt.Sprintf("%s:%d:%s", saltBase64, cfg.PBKDF2Iterations, hashBase64)
	return storedStr, nil
}

// VerifyPBKDF2 verifies a password against a stored PBKDF2 hash
func VerifyPBKDF2(password string, storedStr string) (bool, error) {
	parts := strings.Split(storedStr, ":")
	if len(parts) != 3 {
		return false, errors.New("invalid stored hash format")
	}

	saltBase64 := parts[0]
	iterStr := parts[1]
	hashBase64 := parts[2]

	iterations, err := strconv.Atoi(iterStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse iteration count: %w", err)
	}
	if iterations <= 0 {
		return false, errors.New("iteration count must be greater than 0")
	}

	salt, err := base64.StdEncoding.DecodeString(saltBase64)
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	originalHash, err := base64.StdEncoding.DecodeString(hashBase64)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	globalSalt := DefaultSalt
	passwordWithGlobalSalt := password + globalSalt

	newHash := pbkdf2.Key(
		[]byte(passwordWithGlobalSalt),
		salt,
		iterations,
		len(originalHash),
		sha256.New,
	)

	if subtle.ConstantTimeCompare(newHash, originalHash) == 1 {
		return true, nil
	}
	return false, nil
}

// ====================== Argon2 ======================

// Argon2 configuration struct for Argon2id password hashing
type Argon2 struct {
	argon2Time    int // Number of iterations
	argon2Memory  int // Memory usage in KB
	argon2Threads int // Number of parallel threads
	argon2KeyLen  int // Length of the derived key in bytes
	saltLen       int // Length of the random salt in bytes
}

// DefaultArgon2 returns an Argon2 configuration with secure default values
func DefaultArgon2() Argon2 {
	return Argon2{
		argon2Time:    3,         // 3 iterations
		argon2Memory:  64 * 1024, // 64 MB
		argon2Threads: 4,         // 4 parallel threads
		argon2KeyLen:  32,        // 256 bits
		saltLen:       16,        // 128 bits
	}
}

// CreateArgon2 generates an Argon2id hash for the given password using the provided configuration.
// Returns a base64-encoded string in format: salt:time:memory:threads:hash
func CreateArgon2(cfg Argon2, password string) (string, error) {
	salt := make([]byte, cfg.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	globalSalt := DefaultSalt
	pwd := []byte(password + globalSalt)

	hash := argon2.IDKey(
		pwd,
		salt,
		uint32(cfg.argon2Time),
		uint32(cfg.argon2Memory),
		uint8(cfg.argon2Threads),
		uint32(cfg.argon2KeyLen),
	)

	saltB64 := base64.StdEncoding.EncodeToString(salt)
	hashB64 := base64.StdEncoding.EncodeToString(hash)
	storedStr := fmt.Sprintf("%s:%d:%d:%d:%s", saltB64, cfg.argon2Time, cfg.argon2Memory, cfg.argon2Threads, hashB64)
	return storedStr, nil
}

// VerifyArgon2 verifies a password against a stored Argon2 hash
func VerifyArgon2(password, storedHash string) (bool, error) {
	parts := strings.Split(storedHash, ":")
	if len(parts) != 5 {
		return false, fmt.Errorf("invalid hash format, expected 5 parts, got %d", len(parts))
	}

	saltB64 := parts[0]
	timeStr := parts[1]
	memoryStr := parts[2]
	threadsStr := parts[3]
	hashB64 := parts[4]

	time, err := strconv.Atoi(timeStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse time: %w", err)
	}

	memory, err := strconv.Atoi(memoryStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse memory: %w", err)
	}

	threads, err := strconv.Atoi(threadsStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse threads: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	originalHash, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	globalSalt := DefaultSalt
	pwd := []byte(password + globalSalt)

	newHash := argon2.IDKey(
		pwd,
		salt,
		uint32(time),
		uint32(memory),
		uint8(threads),
		uint32(len(originalHash)),
	)

	return subtle.ConstantTimeCompare(newHash, originalHash) == 1, nil
}

// ====================== scrypt ======================

// Scrypt configuration struct for scrypt password hashing
type Scrypt struct {
	scryptN      int // CPU/memory cost parameter (must be power of 2)
	scryptR      int // Block size parameter
	scryptP      int // Parallelization parameter
	scryptKeyLen int // Length of the derived key in bytes
	saltLen      int // Length of the random salt in bytes
}

// DefaultScrypt returns a Scrypt configuration with secure default values
func DefaultScrypt() Scrypt {
	return Scrypt{
		scryptN:      1 << 14, // 16384 (2^14)
		scryptR:      8,       // Block size
		scryptP:      1,       // Parallelization
		scryptKeyLen: 32,      // 256 bits
		saltLen:      16,      // 128 bits
	}
}

// CreateScrypt generates a scrypt hash for the given password using the provided configuration.
// Returns a base64-encoded string in format: salt:N:r:p:hash
func CreateScrypt(cfg Scrypt, password string) (string, error) {
	salt := make([]byte, cfg.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	globalSalt := DefaultSalt
	pwd := []byte(password + globalSalt)

	hash, err := scrypt.Key(pwd, salt, cfg.scryptN, cfg.scryptR, cfg.scryptP, cfg.scryptKeyLen)
	if err != nil {
		return "", fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	saltB64 := base64.StdEncoding.EncodeToString(salt)
	hashB64 := base64.StdEncoding.EncodeToString(hash)
	storedStr := fmt.Sprintf("%s:%d:%d:%d:%s", saltB64, cfg.scryptN, cfg.scryptR, cfg.scryptP, hashB64)
	return storedStr, nil
}

// VerifyScrypt verifies a password against a stored scrypt hash
func VerifyScrypt(password, storedHash string) (bool, error) {
	parts := strings.Split(storedHash, ":")
	if len(parts) != 5 {
		return false, errors.New("invalid hash format")
	}

	saltB64 := parts[0]
	nStr := parts[1]
	rStr := parts[2]
	pStr := parts[3]
	hashB64 := parts[4]

	n, err := strconv.Atoi(nStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse N parameter: %w", err)
	}

	r, err := strconv.Atoi(rStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse r parameter: %w", err)
	}

	p, err := strconv.Atoi(pStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse p parameter: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	originalHash, err := base64.StdEncoding.DecodeString(hashB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	globalSalt := DefaultSalt
	pwd := []byte(password + globalSalt)

	newHash, err := scrypt.Key(pwd, salt, n, r, p, len(originalHash))
	if err != nil {
		return false, fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	return subtle.ConstantTimeCompare(newHash, originalHash) == 1, nil
}

// ====================== bcrypt ======================

// CreateBcrypt generates a bcrypt hash for the given password with the specified cost.
// Cost should be between 4 and 31, with 12-14 being recommended for most applications.
func CreateBcrypt(cost int, password string) (string, error) {
	globalSalt := DefaultSalt
	pwd := []byte(password + globalSalt)

	hash, err := bcrypt.GenerateFromPassword(pwd, cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash generation failed: %w", err)
	}

	return string(hash), nil
}

// VerifyBcrypt verifies a password against a stored bcrypt hash
func VerifyBcrypt(password, storedHash string) bool {
	globalSalt := DefaultSalt
	pwd := []byte(password + globalSalt)

	err := bcrypt.CompareHashAndPassword([]byte(storedHash), pwd)
	return err == nil
}
