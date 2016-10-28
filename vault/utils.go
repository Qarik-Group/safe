package vault

import "strings"

// ParsePath splits the given path string into its respective secret path
//   and contained key parts
func ParsePath(path string) (secret, key string) {
	secret = path
	if idx := strings.LastIndex(path, ":"); idx >= 0 {
		secret = path[:idx]
		key = path[idx+1:]
	}
	return
}
