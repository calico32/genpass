// Package genpass provides functions for generating random passwords and
// getting information about them.
package genpass

import (
	"crypto/rand"
	"math/big"
	"slices"
)

const (
	CharsetHex      = "abcdef0123456789"
	CharsetLower    = "abcdefghijklmnopqrstuvwxyz"
	CharsetUpper    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	CharsetAlpha    = CharsetLower + CharsetUpper
	CharsetAlphaNum = CharsetAlpha + CharsetNum
	CharsetNum      = "0123456789"
	CharsetSpecial  = "!@#$%^&*()_"
	CharsetAll      = CharsetAlpha + CharsetNum + CharsetSpecial
)

// Generate generates a random password of the specified length using the given
// charset. It chooses cryptographically secure random numbers to select
// characters from the charset.
func Generate(charset string, length int) string {
	chars := []rune(charset)
	slices.Sort(chars)

	charsetLen := big.NewInt(int64(len(chars)))
	password := make([]rune, length)
	for i := range length {
		j, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			// should never happen
			panic(err)
		}
		password[i] = chars[j.Int64()]
	}

	return string(password)
}

// NormalizeCharset normalizes the charset by removing duplicates and sorting
// the characters in ascending order.
func NormalizeCharset(charset string) string {
	chars := []rune(charset)
	slices.Sort(chars)
	return string(chars)
}
