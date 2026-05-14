package easyhash

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Policy describes when a stored hash should be upgraded.
type Policy struct {
	PreferredAlgorithm Algorithm
	Argon2id           Argon2
	PBKDF2             PBKDF2
	Scrypt             Scrypt
	BcryptCost         int
	AllowLegacyMD5     bool
}

// DefaultPolicy returns the default migration target for the high-level API.
func DefaultPolicy() Policy {
	options := DefaultOptions()
	return Policy{
		PreferredAlgorithm: options.Algorithm,
		Argon2id:           options.Argon2id,
		PBKDF2:             options.PBKDF2,
		Scrypt:             options.Scrypt,
		BcryptCost:         options.BcryptCost,
	}
}

// StrongPolicy uses more conservative defaults for new password hashes.
func StrongPolicy() Policy {
	policy := DefaultPolicy()
	policy.Argon2id.argon2Time = 4
	policy.Argon2id.argon2Memory = 128 * 1024
	policy.BcryptCost = 14
	policy.PBKDF2.PBKDF2Iterations = 600000
	policy.Scrypt.scryptN = 1 << 15
	return policy
}

// LowMemoryPolicy keeps Argon2id resource usage lower for constrained environments.
func LowMemoryPolicy() Policy {
	policy := DefaultPolicy()
	policy.Argon2id.argon2Memory = 32 * 1024
	policy.Argon2id.argon2Threads = 2
	return policy
}

// NeedsRehash reports whether a stored hash should be upgraded to match the policy.
func NeedsRehash(encodedHash string, policy Policy) (bool, error) {
	algorithm, err := Identify(encodedHash)
	if err != nil {
		return false, err
	}

	if algorithm == AlgorithmMD5 {
		return !(policy.AllowLegacyMD5 && policy.PreferredAlgorithm == AlgorithmMD5), nil
	}

	if policy.PreferredAlgorithm != "" && algorithm != policy.PreferredAlgorithm {
		return true, nil
	}

	if algorithm != AlgorithmBcrypt && !strings.HasPrefix(encodedHash, easyHashPrefix) {
		return true, nil
	}

	switch algorithm {
	case AlgorithmArgon2id:
		if !strings.HasPrefix(encodedHash, easyHashPrefix) {
			return true, nil
		}
		parsed, err := parseEasyHash(encodedHash)
		if err != nil {
			return false, err
		}
		return parsed.Params["t"] != policy.Argon2id.argon2Time ||
			parsed.Params["m"] != policy.Argon2id.argon2Memory ||
			parsed.Params["p"] != policy.Argon2id.argon2Threads ||
			parsed.Params["l"] != policy.Argon2id.argon2KeyLen, nil
	case AlgorithmPBKDF2:
		if !strings.HasPrefix(encodedHash, easyHashPrefix) {
			return true, nil
		}
		parsed, err := parseEasyHash(encodedHash)
		if err != nil {
			return false, err
		}
		return parsed.Params["i"] != policy.PBKDF2.PBKDF2Iterations ||
			parsed.Params["l"] != policy.PBKDF2.PBKDF2KeyLength, nil
	case AlgorithmScrypt:
		if !strings.HasPrefix(encodedHash, easyHashPrefix) {
			return true, nil
		}
		parsed, err := parseEasyHash(encodedHash)
		if err != nil {
			return false, err
		}
		return parsed.Params["n"] != policy.Scrypt.scryptN ||
			parsed.Params["r"] != policy.Scrypt.scryptR ||
			parsed.Params["p"] != policy.Scrypt.scryptP ||
			parsed.Params["l"] != policy.Scrypt.scryptKeyLen, nil
	case AlgorithmBcrypt:
		cost, err := bcrypt.Cost([]byte(encodedHash))
		if err != nil {
			return false, fmt.Errorf("easyhash: parse bcrypt cost: %w", err)
		}
		return cost != policy.BcryptCost, nil
	default:
		return false, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, algorithm)
	}
}

// VerifyAndUpgrade verifies a password and returns a replacement hash when policy requires it.
func VerifyAndUpgrade(password, encodedHash string, policy Policy) (ok bool, newHash string, upgraded bool, err error) {
	ok, err = Verify(password, encodedHash)
	if err != nil || !ok {
		return ok, "", false, err
	}

	need, err := NeedsRehash(encodedHash, policy)
	if err != nil || !need {
		return true, "", false, err
	}

	newHash, err = Hash(password, optionsFromPolicy(policy)...)
	if err != nil {
		return true, "", false, err
	}

	return true, newHash, true, nil
}

func optionsFromPolicy(policy Policy) []Option {
	options := []Option{WithArgon2idConfig(policy.Argon2id)}

	switch policy.PreferredAlgorithm {
	case AlgorithmPBKDF2:
		options = []Option{WithPBKDF2Config(policy.PBKDF2)}
	case AlgorithmScrypt:
		options = []Option{WithScryptConfig(policy.Scrypt)}
	case AlgorithmBcrypt:
		options = []Option{WithBcryptCost(policy.BcryptCost)}
	case AlgorithmArgon2id, "":
		options = []Option{WithArgon2idConfig(policy.Argon2id)}
	}

	return options
}
