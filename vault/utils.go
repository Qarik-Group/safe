package vault

import (
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// ParsePath splits the given path string into its respective secret path
//   and contained key parts
func ParsePath(path string) (secret, key string, version uint64) {
	secret = path
	if idx := strings.LastIndex(path, "^"); idx >= 0 {
		versionString := path[idx+1:]
		var err error
		version, err = strconv.ParseUint(versionString, 10, 64)
		if err == nil {
			path = path[:idx]
			secret = path
		}
	}

	if idx := strings.LastIndex(path, ":"); idx >= 0 {
		secret = path[:idx]
		key = path[idx+1:]
	}

	secret = Canonicalize(secret)
	return
}

// EncodePath creates a safe-friendly canonical path for the given arguments
func EncodePath(path, key string, version uint64) string {
	if key != "" {
		path += ":" + key
	}

	if version != 0 {
		path += "^" + strconv.FormatUint(version, 10)
	}

	return path
}

// PathHasKey returns true if the given path has a key specified in its syntax.
// False otherwise.
func PathHasKey(path string) bool {
	_, key, _ := ParsePath(path)
	return key != ""
}

func Canonicalize(p string) string {
	p = strings.TrimSuffix(p, "/")
	p = strings.TrimPrefix(p, "/")

	re := regexp.MustCompile("//+")
	p = re.ReplaceAllString(p, "/")

	return p
}

func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("USERPROFILE")
		if home == "" {
			home = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		}
		return home
	}
	return os.Getenv("HOME")
}
