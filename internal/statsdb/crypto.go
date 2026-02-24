package statsdb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Encrypted backup format:
//   magic (5 bytes): "WGOB\x01"
//   salt  (32 bytes): random, for Argon2id
//   nonce (12 bytes): random, for AES-256-GCM
//   ciphertext (rest): AES-256-GCM encrypted data (includes 16-byte auth tag)

var encryptedMagic = []byte("WGOB\x01")

const (
	saltSize  = 32
	nonceSize = 12
)

// deriveKey derives a 32-byte AES key from password and salt using Argon2id.
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
}

// EncryptBackup reads plaintext from r, encrypts with password, and writes to w.
func EncryptBackup(w io.Writer, r io.Reader, password string) error {
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("statsdb: read for encrypt: %w", err)
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("statsdb: generate salt: %w", err)
	}

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("statsdb: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("statsdb: gcm: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("statsdb: generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	if _, err := w.Write(encryptedMagic); err != nil {
		return fmt.Errorf("statsdb: write magic: %w", err)
	}
	if _, err := w.Write(salt); err != nil {
		return fmt.Errorf("statsdb: write salt: %w", err)
	}
	if _, err := w.Write(nonce); err != nil {
		return fmt.Errorf("statsdb: write nonce: %w", err)
	}
	if _, err := w.Write(ciphertext); err != nil {
		return fmt.Errorf("statsdb: write ciphertext: %w", err)
	}
	return nil
}

// DecryptBackup reads an encrypted backup from r, decrypts with password, and writes plaintext to w.
// The caller must have already verified the magic header (first 5 bytes).
func DecryptBackup(w io.Writer, data []byte, password string) error {
	header := len(encryptedMagic) + saltSize + nonceSize
	if len(data) < header {
		return fmt.Errorf("statsdb: encrypted backup too short")
	}

	salt := data[len(encryptedMagic) : len(encryptedMagic)+saltSize]
	nonce := data[len(encryptedMagic)+saltSize : header]
	ciphertext := data[header:]

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("statsdb: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("statsdb: gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("statsdb: decryption failed (wrong password?): %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return fmt.Errorf("statsdb: write decrypted: %w", err)
	}
	return nil
}

// IsEncryptedBackup checks whether data starts with the encrypted backup magic header.
func IsEncryptedBackup(data []byte) bool {
	if len(data) < len(encryptedMagic) {
		return false
	}
	for i, b := range encryptedMagic {
		if data[i] != b {
			return false
		}
	}
	return true
}
