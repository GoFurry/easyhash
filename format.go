package easyhash

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

const (
	easyHashPrefix  = "$easyhash$"
	easyHashVersion = "v=1"
)

type parsedEasyHash struct {
	Algorithm Algorithm
	Params    map[string]int
	Salt      string
	Digest    string
}

func encodeEasyHash(algorithm Algorithm, params, salt, digest string) string {
	return fmt.Sprintf("%s%s$%s$%s$%s$%s", easyHashPrefix, easyHashVersion, algorithm, params, salt, digest)
}

func parseEasyHash(encoded string) (parsedEasyHash, error) {
	if !strings.HasPrefix(encoded, easyHashPrefix) {
		return parsedEasyHash{}, ErrInvalidHashFormat
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 7 {
		return parsedEasyHash{}, fmt.Errorf("%w: expected 7 parts, got %d", ErrInvalidHashFormat, len(parts))
	}
	if parts[1] != "easyhash" || parts[2] != easyHashVersion {
		return parsedEasyHash{}, ErrInvalidHashFormat
	}

	params, err := parseParamMap(parts[4])
	if err != nil {
		return parsedEasyHash{}, err
	}

	parsed := parsedEasyHash{
		Algorithm: Algorithm(parts[3]),
		Params:    params,
		Salt:      parts[5],
		Digest:    parts[6],
	}

	if err := validateParsedEasyHash(parsed); err != nil {
		return parsedEasyHash{}, err
	}

	return parsed, nil
}

func parseParamMap(raw string) (map[string]int, error) {
	params := make(map[string]int)
	if raw == "" {
		return nil, ErrInvalidHashFormat
	}

	for _, part := range strings.Split(raw, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			return nil, ErrInvalidHashFormat
		}
		if _, exists := params[kv[0]]; exists {
			return nil, fmt.Errorf("%w: duplicate parameter %q", ErrInvalidHashFormat, kv[0])
		}

		value, err := strconv.Atoi(kv[1])
		if err != nil || value <= 0 {
			return nil, fmt.Errorf("%w: invalid parameter %q", ErrInvalidHashFormat, kv[0])
		}
		params[kv[0]] = value
	}

	return params, nil
}

func validateParsedEasyHash(parsed parsedEasyHash) error {
	if parsed.Salt == "" || parsed.Digest == "" {
		return ErrInvalidHashFormat
	}

	salt, err := base64.StdEncoding.DecodeString(parsed.Salt)
	if err != nil || len(salt) == 0 {
		return fmt.Errorf("%w: invalid salt", ErrInvalidHashFormat)
	}

	digest, err := base64.StdEncoding.DecodeString(parsed.Digest)
	if err != nil || len(digest) == 0 {
		return fmt.Errorf("%w: invalid digest", ErrInvalidHashFormat)
	}

	switch parsed.Algorithm {
	case AlgorithmPBKDF2:
		return validateParamSet(parsed.Params, "i", "l")
	case AlgorithmArgon2id:
		return validateParamSet(parsed.Params, "m", "t", "p", "l")
	case AlgorithmScrypt:
		if err := validateParamSet(parsed.Params, "n", "r", "p", "l"); err != nil {
			return err
		}
		if !isPowerOfTwo(parsed.Params["n"]) {
			return fmt.Errorf("%w: invalid parameter %q", ErrInvalidHashFormat, "n")
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, parsed.Algorithm)
	}
}

func validateParamSet(params map[string]int, required ...string) error {
	if len(params) != len(required) {
		return ErrInvalidHashFormat
	}

	allowed := make(map[string]struct{}, len(required))
	for _, key := range required {
		allowed[key] = struct{}{}
		if _, ok := params[key]; !ok {
			return fmt.Errorf("%w: missing parameter %q", ErrInvalidHashFormat, key)
		}
	}

	for key := range params {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("%w: unexpected parameter %q", ErrInvalidHashFormat, key)
		}
	}

	return nil
}

func decodedLength(b64 string) (int, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func isLegacyMD5Hash(encoded string) bool {
	if len(encoded) != 32 {
		return false
	}

	for _, ch := range encoded {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		case ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}

	return true
}

func identifyLegacyFivePartHash(encoded string) (Algorithm, error) {
	parts := strings.Split(encoded, ":")
	if len(parts) != 5 {
		return "", ErrInvalidHashFormat
	}

	first, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", ErrInvalidHashFormat
	}

	second, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", ErrInvalidHashFormat
	}

	third, err := strconv.Atoi(parts[3])
	if err != nil {
		return "", ErrInvalidHashFormat
	}

	if isPowerOfTwo(first) && first >= 1024 && second > 0 && second <= 128 && third > 0 && third <= 16 {
		return AlgorithmScrypt, nil
	}

	return AlgorithmArgon2id, nil
}

func isPowerOfTwo(value int) bool {
	return value > 0 && value&(value-1) == 0
}
