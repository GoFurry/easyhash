# Examples

This directory contains runnable examples for `easyhash`.

## Available Examples

- `quickstart/main.go`: the recommended first example. Shows the default `Hash` / `Verify` / `Identify` / `NeedsRehash` path.
- `algorithms/main.go`: shows how to explicitly choose PBKDF2, Argon2id, scrypt, or bcrypt and verify the generated hashes.
- `migration/main.go`: shows a realistic login-time upgrade flow from a legacy hash to the current default policy.

## How To Run

```bash
go run ./examples/quickstart
go run ./examples/algorithms
go run ./examples/migration
```

## Suggested Reading Order

1. Start with `quickstart` to understand the default high-level path.
2. Open `algorithms` if your project needs explicit algorithm control.
3. Open `migration` if you are integrating `easyhash` into an existing user table with legacy hashes.
