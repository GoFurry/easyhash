package easyhash_test

import (
	"fmt"

	"github.com/gofurry/easyhash"
)

func ExampleHash() {
	hash, err := easyhash.Hash("12345678")
	if err != nil {
		fmt.Println("error")
		return
	}

	algorithm, err := easyhash.Identify(hash)
	if err != nil {
		fmt.Println("error")
		return
	}

	fmt.Println(algorithm)
	// Output: pbkdf2-sha256
}

func ExampleVerifyAndUpgrade() {
	legacy, err := easyhash.CreateArgon2(easyhash.DefaultArgon2(), "12345678")
	if err != nil {
		fmt.Println("error")
		return
	}

	ok, newHash, upgraded, err := easyhash.VerifyAndUpgrade("12345678", legacy, easyhash.DefaultPolicy())
	if err != nil {
		fmt.Println("error")
		return
	}

	algorithm, err := easyhash.Identify(newHash)
	if err != nil {
		fmt.Println("error")
		return
	}

	fmt.Println(ok, upgraded, algorithm)
	// Output: true true pbkdf2-sha256
}
