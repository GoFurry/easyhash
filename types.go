package easyhash

// Algorithm identifies the password hashing algorithm used by a stored hash.
type Algorithm string

const (
	AlgorithmArgon2id Algorithm = "argon2id"
	AlgorithmBcrypt   Algorithm = "bcrypt"
	AlgorithmPBKDF2   Algorithm = "pbkdf2-sha256"
	AlgorithmScrypt   Algorithm = "scrypt"
	AlgorithmMD5      Algorithm = "md5"
)
