package easyhash

import "testing"

func TestHashVerifyDefault(t *testing.T) {
	encoded, err := Hash(testPassword)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	algorithm, err := Identify(encoded)
	if err != nil {
		t.Fatalf("Identify failed: %v", err)
	}
	if algorithm != AlgorithmPBKDF2 {
		t.Fatalf("unexpected algorithm: %s", algorithm)
	}

	ok, err := Verify(testPassword, encoded)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatal("expected password to verify")
	}
}

func TestHashVerifyBcrypt(t *testing.T) {
	encoded, err := Hash(testPassword, WithBcryptCost(10))
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	algorithm, err := Identify(encoded)
	if err != nil {
		t.Fatalf("Identify failed: %v", err)
	}
	if algorithm != AlgorithmBcrypt {
		t.Fatalf("unexpected algorithm: %s", algorithm)
	}

	ok, err := Verify(testPassword, encoded)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatal("expected password to verify")
	}
}

func TestVerifyLegacyHashes(t *testing.T) {
	pbkdf2Hash, err := CreatePBKDF2(DefaultPBKDF2(), testPassword)
	if err != nil {
		t.Fatalf("CreatePBKDF2 failed: %v", err)
	}
	ok, err := Verify(testPassword, pbkdf2Hash)
	if err != nil || !ok {
		t.Fatalf("Verify legacy PBKDF2 failed: ok=%v err=%v", ok, err)
	}

	argon2Hash, err := CreateArgon2(DefaultArgon2(), testPassword)
	if err != nil {
		t.Fatalf("CreateArgon2 failed: %v", err)
	}
	ok, err = Verify(testPassword, argon2Hash)
	if err != nil || !ok {
		t.Fatalf("Verify legacy Argon2 failed: ok=%v err=%v", ok, err)
	}

	scryptHash, err := CreateScrypt(DefaultScrypt(), testPassword)
	if err != nil {
		t.Fatalf("CreateScrypt failed: %v", err)
	}
	ok, err = Verify(testPassword, scryptHash)
	if err != nil || !ok {
		t.Fatalf("Verify legacy scrypt failed: ok=%v err=%v", ok, err)
	}
}

func TestNeedsRehashLegacyPBKDF2(t *testing.T) {
	legacy, err := CreatePBKDF2(DefaultPBKDF2(), testPassword)
	if err != nil {
		t.Fatalf("CreatePBKDF2 failed: %v", err)
	}

	need, err := NeedsRehash(legacy, DefaultPolicy())
	if err != nil {
		t.Fatalf("NeedsRehash failed: %v", err)
	}
	if !need {
		t.Fatal("expected legacy PBKDF2 hash to require migration")
	}
}

func TestVerifyAndUpgradeLegacyPBKDF2(t *testing.T) {
	legacy, err := CreatePBKDF2(DefaultPBKDF2(), testPassword)
	if err != nil {
		t.Fatalf("CreatePBKDF2 failed: %v", err)
	}

	ok, upgradedHash, upgraded, err := VerifyAndUpgrade(testPassword, legacy, DefaultPolicy())
	if err != nil {
		t.Fatalf("VerifyAndUpgrade failed: %v", err)
	}
	if !ok {
		t.Fatal("expected password to verify")
	}
	if !upgraded {
		t.Fatal("expected legacy hash to be upgraded")
	}
	if upgradedHash == "" {
		t.Fatal("expected upgraded hash output")
	}
	if _, err := parseEasyHash(upgradedHash); err != nil {
		t.Fatalf("expected upgraded hash to use easyhash format: %v", err)
	}

	algorithm, err := Identify(upgradedHash)
	if err != nil {
		t.Fatalf("Identify upgraded hash failed: %v", err)
	}
	if algorithm != AlgorithmPBKDF2 {
		t.Fatalf("unexpected upgraded algorithm: %s", algorithm)
	}
}
