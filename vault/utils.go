package vault

import (
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var keyColonRegexp = regexp.MustCompile(`[^\\](:)`)
var versionCaretRegexp = regexp.MustCompile(`[^\\](\^)`)

// ParsePath splits the given path string into its respective secret path
// and contained key parts
func ParsePath(path string) (secret, key string, version uint64) {
	secret = path
	var err error

	matches := versionCaretRegexp.FindAllStringSubmatchIndex(path, -1)
	if len(matches) > 0 { //if there exists a version caret
		caretIdx := matches[len(matches)-1]
		caretStart, caretEnd := caretIdx[len(caretIdx)-2], caretIdx[len(caretIdx)-1]
		versionString := path[caretEnd:]
		version, err = strconv.ParseUint(versionString, 10, 64)
		if err == nil {
			path = path[:caretStart]
			secret = path
		}
	}

	matches = keyColonRegexp.FindAllStringSubmatchIndex(path, -1)
	if len(matches) > 0 { //if there exists a path colon
		colonIdx := matches[len(matches)-1]
		colonStart, colonEnd := colonIdx[len(colonIdx)-2], colonIdx[len(colonIdx)-1]
		key = path[colonEnd:]
		secret = path[:colonStart]
	}

	//unescape escaped characters
	secret = strings.ReplaceAll(secret, `\:`, ":")
	secret = strings.ReplaceAll(secret, `\^`, "^")
	key = strings.ReplaceAll(key, `\:`, ":")
	key = strings.ReplaceAll(key, `\^`, "^")

	secret = Canonicalize(secret)
	return
}

// EscapePathSegment is the reverse of ParsePath for an output secret or key
// segment; whereas that function unescapes colons and carets, this function
// reescapes them so that they can be run through that function again.
func EscapePathSegment(segment string) string {
	segment = strings.ReplaceAll(segment, ":", `\:`)
	segment = strings.ReplaceAll(segment, "^", `\^`)
	return segment
}

// EncodePath creates a safe-friendly canonical path for the given arguments
func EncodePath(path, key string, version uint64) string {
	path = EscapePathSegment(path)
	if key != "" {
		key = EscapePathSegment(key)
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

// PathHasVersion returns true if the given path has a version specified in its
// syntax.
// False otherwise.
func PathHasVersion(path string) bool {
	_, _, version := ParsePath(path)
	return version != 0
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
