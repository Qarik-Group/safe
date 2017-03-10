package cli

import (
	"fmt"
	"strings"
)

/* validateLevel checks to make sure there is no overlap between
   the given context and the short/long options seen at a higher level. */
func validateLevel(c context, parents []string, shorts string, longs map[string]bool) error {
	where := "(at global level)"
	if len(parents) > 0 {
		where = fmt.Sprintf("(in `%s` sub-command)", strings.Join(parents, " "))
	}
	for _, o := range c.Options {
		if i := strings.IndexAny(o.Shorts, shorts); i >= 0 {
			return fmt.Errorf("short option `-%c` reused ambiguously %s", o.Shorts[i], where)
		}
		shorts += o.Shorts
		for _, long := range o.Longs {
			if _, ok := longs[long]; ok {
				return fmt.Errorf("long option `--%s` reused ambiguously %s", long, where)
			}
			longs[long] = true
		}
	}

	for cmd, sub := range c.Subs {
		copied := make(map[string]bool, len(longs))
		for k, v := range longs {
			copied[k] = v
		}

		if err := validateLevel(sub, append(parents, cmd), shorts, copied); err != nil {
			return err
		}
	}

	return nil
}

func validate(c context) error {
	return validateLevel(c, make([]string, 0), "", make(map[string]bool))
}
