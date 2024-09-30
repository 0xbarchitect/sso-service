package helper

import (
	"crypto/rand"
	"encoding/hex"
)

func GenerateRandomStringWithLength(length int) (string, error) {
	var Rando = rand.Reader
	b := make([]byte, length)
	_, err := Rando.Read(b)
	return hex.EncodeToString(b), err
}
