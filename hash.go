package easyhash

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"
)

// Hash hashes a password using the selected high-level algorithm.
// The default algorithm is Argon2id.
func Hash(password string, opts ...Option) (string, error) {
	cfg := applyOptions(opts...)

	switch cfg.Algorithm {
	case AlgorithmArgon2id:
		legacy, err := CreateArgon2(cfg.Argon2id, password)
		if err != nil {
			return "", err
		}
		return encodeArgon2Hash(legacy)
	case AlgorithmPBKDF2:
		legacy, err := CreatePBKDF2(cfg.PBKDF2, password)
		if err != nil {
			return "", err
		}
		return encodePBKDF2Hash(legacy)
	case AlgorithmScrypt:
		legacy, err := CreateScrypt(cfg.Scrypt, password)
		if err != nil {
			return "", err
		}
		return encodeScryptHash(legacy)
	case AlgorithmBcrypt:
		return CreateBcrypt(cfg.BcryptCost, password)
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, cfg.Algorithm)
	}
}

// Verify verifies a password against either the new easyhash format or legacy hashes.
func Verify(password, encodedHash string) (bool, error) {
	algorithm, err := Identify(encodedHash)
	if err != nil {
		return false, err
	}

	switch algorithm {
	case AlgorithmArgon2id:
		return verifyArgon2Hash(password, encodedHash)
	case AlgorithmPBKDF2:
		return verifyPBKDF2Hash(password, encodedHash)
	case AlgorithmScrypt:
		return verifyScryptHash(password, encodedHash)
	case AlgorithmBcrypt:
		return VerifyBcrypt(password, encodedHash), nil
	case AlgorithmMD5:
		sum := CreateMD5(password)
		return subtle.ConstantTimeCompare([]byte(strings.ToLower(sum)), []byte(strings.ToLower(encodedHash))) == 1, nil
	default:
		return false, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, algorithm)
	}
}

// Identify returns the hashing algorithm used by an encoded hash.
func Identify(encodedHash string) (Algorithm, error) {
	if strings.HasPrefix(encodedHash, easyHashPrefix) {
		parsed, err := parseEasyHash(encodedHash)
		if err != nil {
			return "", err
		}
		return parsed.Algorithm, nil
	}

	if strings.HasPrefix(encodedHash, "$2a$") || strings.HasPrefix(encodedHash, "$2b$") || strings.HasPrefix(encodedHash, "$2y$") {
		return AlgorithmBcrypt, nil
	}

	parts := strings.Split(encodedHash, ":")
	switch len(parts) {
	case 3:
		return AlgorithmPBKDF2, nil
	case 5:
		return identifyLegacyFivePartHash(encodedHash)
	}

	if isLegacyMD5Hash(encodedHash) {
		return AlgorithmMD5, nil
	}

	return "", ErrInvalidHashFormat
}

func encodePBKDF2Hash(legacy string) (string, error) {
	parts := strings.Split(legacy, ":")
	if len(parts) != 3 {
		return "", ErrInvalidHashFormat
	}

	keyLen, err := decodedLength(parts[2])
	if err != nil {
		return "", err
	}

	iterations, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", err
	}

	return encodeEasyHash(
		AlgorithmPBKDF2,
		fmt.Sprintf("i=%d,l=%d", iterations, keyLen),
		parts[0],
		parts[2],
	), nil
}

func encodeArgon2Hash(legacy string) (string, error) {
	parts := strings.Split(legacy, ":")
	if len(parts) != 5 {
		return "", ErrInvalidHashFormat
	}

	timeCost, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", err
	}
	memory, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", err
	}
	threads, err := strconv.Atoi(parts[3])
	if err != nil {
		return "", err
	}
	keyLen, err := decodedLength(parts[4])
	if err != nil {
		return "", err
	}

	return encodeEasyHash(
		AlgorithmArgon2id,
		fmt.Sprintf("m=%d,t=%d,p=%d,l=%d", memory, timeCost, threads, keyLen),
		parts[0],
		parts[4],
	), nil
}

func encodeScryptHash(legacy string) (string, error) {
	parts := strings.Split(legacy, ":")
	if len(parts) != 5 {
		return "", ErrInvalidHashFormat
	}

	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", err
	}
	r, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", err
	}
	p, err := strconv.Atoi(parts[3])
	if err != nil {
		return "", err
	}
	keyLen, err := decodedLength(parts[4])
	if err != nil {
		return "", err
	}

	return encodeEasyHash(
		AlgorithmScrypt,
		fmt.Sprintf("n=%d,r=%d,p=%d,l=%d", n, r, p, keyLen),
		parts[0],
		parts[4],
	), nil
}

func verifyPBKDF2Hash(password, encodedHash string) (bool, error) {
	if !strings.HasPrefix(encodedHash, easyHashPrefix) {
		return VerifyPBKDF2(password, encodedHash)
	}

	parsed, err := parseEasyHash(encodedHash)
	if err != nil {
		return false, err
	}

	iterations, ok := parsed.Params["i"]
	if !ok {
		return false, ErrInvalidHashFormat
	}

	legacy := fmt.Sprintf("%s:%d:%s", parsed.Salt, iterations, parsed.Digest)
	return VerifyPBKDF2(password, legacy)
}

func verifyArgon2Hash(password, encodedHash string) (bool, error) {
	if !strings.HasPrefix(encodedHash, easyHashPrefix) {
		return VerifyArgon2(password, encodedHash)
	}

	parsed, err := parseEasyHash(encodedHash)
	if err != nil {
		return false, err
	}

	timeCost, ok := parsed.Params["t"]
	if !ok {
		return false, ErrInvalidHashFormat
	}
	memory, ok := parsed.Params["m"]
	if !ok {
		return false, ErrInvalidHashFormat
	}
	threads, ok := parsed.Params["p"]
	if !ok {
		return false, ErrInvalidHashFormat
	}

	legacy := fmt.Sprintf("%s:%d:%d:%d:%s", parsed.Salt, timeCost, memory, threads, parsed.Digest)
	return VerifyArgon2(password, legacy)
}

func verifyScryptHash(password, encodedHash string) (bool, error) {
	if !strings.HasPrefix(encodedHash, easyHashPrefix) {
		return VerifyScrypt(password, encodedHash)
	}

	parsed, err := parseEasyHash(encodedHash)
	if err != nil {
		return false, err
	}

	n, ok := parsed.Params["n"]
	if !ok {
		return false, ErrInvalidHashFormat
	}
	r, ok := parsed.Params["r"]
	if !ok {
		return false, ErrInvalidHashFormat
	}
	parallel, ok := parsed.Params["p"]
	if !ok {
		return false, ErrInvalidHashFormat
	}

	legacy := fmt.Sprintf("%s:%d:%d:%d:%s", parsed.Salt, n, r, parallel, parsed.Digest)
	return VerifyScrypt(password, legacy)
}
