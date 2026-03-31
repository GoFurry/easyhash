package easyhash

import (
	"testing"
)

const testPassword = "MySecurePassword123!"

// ====================== Benchmark Tests ======================

func BenchmarkCreateMD5(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CreateMD5(testPassword)
	}
}

func BenchmarkCreatePBKDF2(b *testing.B) {
	cfg := DefaultPBKDF2()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreatePBKDF2(cfg, testPassword)
	}
}

func BenchmarkVerifyPBKDF2(b *testing.B) {
	cfg := DefaultPBKDF2()
	hash, _ := CreatePBKDF2(cfg, testPassword)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyPBKDF2(testPassword, hash)
	}
}

func BenchmarkCreateArgon2(b *testing.B) {
	cfg := DefaultArgon2()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateArgon2(cfg, testPassword)
	}
}

func BenchmarkVerifyArgon2(b *testing.B) {
	cfg := DefaultArgon2()
	hash, _ := CreateArgon2(cfg, testPassword)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyArgon2(testPassword, hash)
	}
}

func BenchmarkCreateScrypt(b *testing.B) {
	cfg := DefaultScrypt()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateScrypt(cfg, testPassword)
	}
}

func BenchmarkVerifyScrypt(b *testing.B) {
	cfg := DefaultScrypt()
	hash, _ := CreateScrypt(cfg, testPassword)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyScrypt(testPassword, hash)
	}
}

func BenchmarkCreateBcrypt(b *testing.B) {
	cost := 12
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateBcrypt(cost, testPassword)
	}
}

func BenchmarkVerifyBcrypt(b *testing.B) {
	cost := 12
	hash, _ := CreateBcrypt(cost, testPassword)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyBcrypt(testPassword, hash)
	}
}

// ====================== Comparative Benchmarks ======================

func BenchmarkArgon2_Fast(b *testing.B) {
	cfg := Argon2{
		argon2Time:    1,
		argon2Memory:  32 * 1024, // 32 MB
		argon2Threads: 2,
		argon2KeyLen:  32,
		saltLen:       16,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateArgon2(cfg, testPassword)
	}
}

func BenchmarkArgon2_Secure(b *testing.B) {
	cfg := Argon2{
		argon2Time:    5,
		argon2Memory:  128 * 1024, // 128 MB
		argon2Threads: 4,
		argon2KeyLen:  32,
		saltLen:       16,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateArgon2(cfg, testPassword)
	}
}

func BenchmarkPBKDF2_Fast(b *testing.B) {
	cfg := PBKDF2{
		PBKDF2Iterations: 50000,
		PBKDF2KeyLength:  32,
		SaltLength:       16,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreatePBKDF2(cfg, testPassword)
	}
}

func BenchmarkPBKDF2_Secure(b *testing.B) {
	cfg := PBKDF2{
		PBKDF2Iterations: 200000,
		PBKDF2KeyLength:  32,
		SaltLength:       16,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreatePBKDF2(cfg, testPassword)
	}
}

func BenchmarkBcrypt_Fast(b *testing.B) {
	cost := 10
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateBcrypt(cost, testPassword)
	}
}

func BenchmarkBcrypt_Secure(b *testing.B) {
	cost := 14
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CreateBcrypt(cost, testPassword)
	}
}

// ====================== Functional Tests ======================

func TestPBKDF2(t *testing.T) {
	cfg := DefaultPBKDF2()
	hash, err := CreatePBKDF2(cfg, testPassword)
	if err != nil {
		t.Fatalf("CreatePBKDF2 failed: %v", err)
	}

	valid, err := VerifyPBKDF2(testPassword, hash)
	if err != nil {
		t.Fatalf("VerifyPBKDF2 failed: %v", err)
	}
	if !valid {
		t.Error("Password verification failed")
	}

	valid, err = VerifyPBKDF2("wrongpassword", hash)
	if err != nil {
		t.Fatalf("VerifyPBKDF2 failed: %v", err)
	}
	if valid {
		t.Error("Wrong password should not verify")
	}
}

func TestArgon2(t *testing.T) {
	cfg := DefaultArgon2()
	hash, err := CreateArgon2(cfg, testPassword)
	if err != nil {
		t.Fatalf("CreateArgon2 failed: %v", err)
	}

	valid, err := VerifyArgon2(testPassword, hash)
	if err != nil {
		t.Fatalf("VerifyArgon2 failed: %v", err)
	}
	if !valid {
		t.Error("Password verification failed")
	}

	valid, err = VerifyArgon2("wrongpassword", hash)
	if err != nil {
		t.Fatalf("VerifyArgon2 failed: %v", err)
	}
	if valid {
		t.Error("Wrong password should not verify")
	}
}

func TestScrypt(t *testing.T) {
	cfg := DefaultScrypt()
	hash, err := CreateScrypt(cfg, testPassword)
	if err != nil {
		t.Fatalf("CreateScrypt failed: %v", err)
	}

	valid, err := VerifyScrypt(testPassword, hash)
	if err != nil {
		t.Fatalf("VerifyScrypt failed: %v", err)
	}
	if !valid {
		t.Error("Password verification failed")
	}

	valid, err = VerifyScrypt("wrongpassword", hash)
	if err != nil {
		t.Fatalf("VerifyScrypt failed: %v", err)
	}
	if valid {
		t.Error("Wrong password should not verify")
	}
}

func TestBcrypt(t *testing.T) {
	cost := 12
	hash, err := CreateBcrypt(cost, testPassword)
	if err != nil {
		t.Fatalf("CreateBcrypt failed: %v", err)
	}

	valid := VerifyBcrypt(testPassword, hash)
	if !valid {
		t.Error("Password verification failed")
	}

	valid = VerifyBcrypt("wrongpassword", hash)
	if valid {
		t.Error("Wrong password should not verify")
	}
}
