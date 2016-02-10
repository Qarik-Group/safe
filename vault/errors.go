package vault

import (
	"fmt"
)

var NotFound error

func init() {
	NotFound = fmt.Errorf("secret not found")
}
