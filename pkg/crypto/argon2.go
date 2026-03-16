package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	timeParam    = 1
	memoryParam  = 64 * 1024
	threadsParam = 4
	keyLen       = 32
	saltLen      = 16
)

// HashSecret hashes a secret using Argon2id with a random salt.
// Returns an encoded string in format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
func HashSecret(secret []byte) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey(secret, salt, timeParam, memoryParam, threadsParam, keyLen)
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memoryParam, timeParam, threadsParam, saltB64, hashB64), nil
}

// VerifySecret checks if the secret matches the stored hash.
func VerifySecret(secret []byte, encodedHash string) (bool, error) {
	salt, hash, timeVal, memoryVal, threadsVal, keyLenVal, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}
	computed := argon2.IDKey(secret, salt, timeVal, memoryVal, uint8(threadsVal), keyLenVal)
	return subtle.ConstantTimeCompare(hash, computed) == 1, nil
}

func decodeHash(encoded string) (salt, hash []byte, timeVal, memoryVal uint32, threadsVal uint32, keyLenVal uint32, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, 0, errors.New("invalid argon2 hash format")
	}
	var m, t, p uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return nil, nil, 0, 0, 0, 0, err
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, 0, 0, 0, 0, err
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, 0, 0, 0, 0, err
	}
	return salt, hash, t, m, p, uint32(len(hash)), nil
}
