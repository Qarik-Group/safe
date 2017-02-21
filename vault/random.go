package vault

import (
	"bytes"
	"math/rand"
	"regexp"
	"time"
)

var chars = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

func random(n int, policy string) string {
	re := regexp.MustCompile("[^" + policy + "]")
	keep := re.ReplaceAllString(chars, "")

	var buffer bytes.Buffer

	for i := 0; i < n; i++ {
		buffer.WriteString(string(keep[rand.Intn(len(keep))]))
	}

	return buffer.String()
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
