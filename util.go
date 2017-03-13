package main

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

func duration(s string) (time.Duration, error) {
	re := regexp.MustCompile(`^(\d+)([HhDdMmYy])$`)
	if m := re.FindStringSubmatch(s); m != nil {
		v, err := strconv.ParseUint(m[1], 10, 0)
		if err != nil {
			return 0, err
		}

		switch m[2] {
		case "H", "h":
			return time.Hour * time.Duration(v), nil
		case "D", "d":
			return time.Hour * time.Duration(24*v), nil
		case "M", "m":
			return time.Hour * time.Duration(24*30*v), nil
		case "Y", "y":
			return time.Hour * time.Duration(24*365*v), nil
		}
	}
	return 0, fmt.Errorf("unrecognized time spec '%s'", s)
}
