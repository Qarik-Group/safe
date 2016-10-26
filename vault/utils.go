package vault

// ParsePath splits the given path string into its respective secret path
//   and contained key parts
func ParsePath(path string) (secret, key string) {
	secret = path
	if len(path) >= 2 { //must contain at least "a:", so two characters
		for i := len(path) - 1; i >= 0; i-- {
			if path[i] == ':' {
				secret = path[0:i]
				key = path[i+1 : len(path)]
				break
			}
		}
	} else if len(path) == 1 && path[0] == ':' { // if just ":"
		secret = ""
	}
	return
}
