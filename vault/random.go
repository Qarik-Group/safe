package vault

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"regexp"
)

var (
	chars = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
)

func random(n int, policy string) (string, error) {
	re := regexp.MustCompile("[^" + policy + "]")
	keep := re.ReplaceAllString(chars, "")

	var buffer bytes.Buffer

	for i := 0; i < n; i++ {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(keep))))
		if err != nil {
			return "", err
		}
		indexInt := index.Int64()
		buffer.WriteString(string(keep[indexInt]))
	}

	return buffer.String(), nil
}
