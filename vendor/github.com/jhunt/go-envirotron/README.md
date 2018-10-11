Envirotron
==========

![Travis CI](https://travis-ci.org/jhunt/go-envirotron.svg?branch=master)

Ever wanted to easily allow users to override configuration values
in a Go program via environment variables, but didn't want to deal
with the tedium of checking that variables are set, and the
harrowing existential crisis of determing what is `true`?

Want no more!

```
package thing

import (
  "fmt"
  env "github.com/jhunt/go-envirotron"
)

type Config struct {
  URL      string `env:"THING_URL"`
  Username string `env:"THING_USERNAME"`
  Password string `env:"THING_PASSWORD"`
}

func main() {
  c := Config{}
  env.Override(&c)

  fmt.Printf("connecting to %s, as %s\n", c.URL, c.Username)
}
```

Happy Hacking!
