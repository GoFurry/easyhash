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

	return parsedEasyHash{
		Algorithm: Algorithm(parts[3]),
		Params:    params,
		Salt:      parts[5],
		Digest:    parts[6],
	}, nil
}

func parseParamMap(raw string) (map[string]int, error) {
	params := make(map[string]int)
	if raw == "" {
		return params, nil
	}

	for _, part := range strings.Split(raw, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, ErrInvalidHashFormat
		}

		value, err := strconv.Atoi(kv[1])
		if err != nil {
			return nil, fmt.Errorf("%w: invalid parameter %q", ErrInvalidHashFormat, kv[0])
		}
		params[kv[0]] = value
	}

	return params, nil
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
