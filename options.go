package easyhash

const DefaultBcryptCost = 12

// Options configures the high-level Hash API.
type Options struct {
	Algorithm  Algorithm
	Argon2id   Argon2
	PBKDF2     PBKDF2
	Scrypt     Scrypt
	BcryptCost int
}

// Option mutates high-level hash options.
type Option func(*Options)

// DefaultOptions returns the default high-level hashing configuration.
func DefaultOptions() Options {
	return Options{
		Algorithm:  AlgorithmArgon2id,
		Argon2id:   DefaultArgon2(),
		PBKDF2:     DefaultPBKDF2(),
		Scrypt:     DefaultScrypt(),
		BcryptCost: DefaultBcryptCost,
	}
}

// WithArgon2id selects Argon2id for Hash.
func WithArgon2id() Option {
	return func(o *Options) {
		o.Algorithm = AlgorithmArgon2id
	}
}

// WithArgon2idConfig overrides the Argon2id configuration for Hash.
func WithArgon2idConfig(cfg Argon2) Option {
	return func(o *Options) {
		o.Algorithm = AlgorithmArgon2id
		o.Argon2id = cfg
	}
}

// WithPBKDF2 selects PBKDF2-SHA256 for Hash.
func WithPBKDF2() Option {
	return func(o *Options) {
		o.Algorithm = AlgorithmPBKDF2
	}
}

// WithPBKDF2Config overrides the PBKDF2 configuration for Hash.
func WithPBKDF2Config(cfg PBKDF2) Option {
	return func(o *Options) {
		o.Algorithm = AlgorithmPBKDF2
		o.PBKDF2 = cfg
	}
}

// WithScrypt selects scrypt for Hash.
func WithScrypt() Option {
	return func(o *Options) {
		o.Algorithm = AlgorithmScrypt
	}
}

// WithScryptConfig overrides the scrypt configuration for Hash.
func WithScryptConfig(cfg Scrypt) Option {
	return func(o *Options) {
		o.Algorithm = AlgorithmScrypt
		o.Scrypt = cfg
	}
}

// WithBcrypt selects bcrypt for Hash.
func WithBcrypt() Option {
	return func(o *Options) {
		o.Algorithm = AlgorithmBcrypt
	}
}

// WithBcryptCost overrides the bcrypt cost for Hash.
func WithBcryptCost(cost int) Option {
	return func(o *Options) {
		o.Algorithm = AlgorithmBcrypt
		o.BcryptCost = cost
	}
}

func applyOptions(opts ...Option) Options {
	cfg := DefaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}
