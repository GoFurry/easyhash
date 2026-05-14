package easyhash

import "testing"

func TestParseEasyHashRejectsUnknownAlgorithm(t *testing.T) {
	_, err := parseEasyHash("$easyhash$v=1$sha256$i=100000,l=32$c2FsdA==$aGFzaA==")
	if err == nil {
		t.Fatal("expected unknown algorithm to fail")
	}
}

func TestParseEasyHashRejectsMissingParameters(t *testing.T) {
	_, err := parseEasyHash("$easyhash$v=1$pbkdf2-sha256$l=32$c2FsdA==$aGFzaA==")
	if err == nil {
		t.Fatal("expected missing parameter to fail")
	}
}

func TestParseEasyHashRejectsUnexpectedParameters(t *testing.T) {
	_, err := parseEasyHash("$easyhash$v=1$pbkdf2-sha256$i=100000,l=32,x=1$c2FsdA==$aGFzaA==")
	if err == nil {
		t.Fatal("expected unexpected parameter to fail")
	}
}

func TestParseEasyHashRejectsDuplicateParameters(t *testing.T) {
	_, err := parseEasyHash("$easyhash$v=1$pbkdf2-sha256$i=100000,i=200000,l=32$c2FsdA==$aGFzaA==")
	if err == nil {
		t.Fatal("expected duplicate parameter to fail")
	}
}

func TestParseEasyHashRejectsInvalidBase64(t *testing.T) {
	_, err := parseEasyHash("$easyhash$v=1$pbkdf2-sha256$i=100000,l=32$not-base64$aGFzaA==")
	if err == nil {
		t.Fatal("expected invalid base64 salt to fail")
	}
}

func TestNeedsRehashReturnsFalseForDefaultHash(t *testing.T) {
	encoded, err := Hash(testPassword)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	need, err := NeedsRehash(encoded, DefaultPolicy())
	if err != nil {
		t.Fatalf("NeedsRehash failed: %v", err)
	}
	if need {
		t.Fatal("expected default hash to match default policy")
	}
}

func TestVerifyAndUpgradeLegacyArgon2ToDefaultPolicy(t *testing.T) {
	legacy, err := CreateArgon2(DefaultArgon2(), testPassword)
	if err != nil {
		t.Fatalf("CreateArgon2 failed: %v", err)
	}

	ok, upgradedHash, upgraded, err := VerifyAndUpgrade(testPassword, legacy, DefaultPolicy())
	if err != nil {
		t.Fatalf("VerifyAndUpgrade failed: %v", err)
	}
	if !ok || !upgraded {
		t.Fatalf("expected upgrade, got ok=%v upgraded=%v", ok, upgraded)
	}

	algorithm, err := Identify(upgradedHash)
	if err != nil {
		t.Fatalf("Identify failed: %v", err)
	}
	if algorithm != AlgorithmPBKDF2 {
		t.Fatalf("unexpected upgraded algorithm: %s", algorithm)
	}
}
