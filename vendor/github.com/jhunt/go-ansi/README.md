ANSI - A Colorful Formatter for Go
==================================

![Travis CI](https://travis-ci.org/jhunt/go-ansi.svg?branch=master)

Ever wanted colorful output from your Golang CLI projects, but
don't want to have to muck up your codebase with unsightly ANSI
escape sequences?

Then this is the module for you!

Usage
-----

`go-ansi` provides a drop-in replacement for `fmt.Printf` and
friends that recognized an additional set of formatter flags for
colorizing output.

```go
import (
  fmt "github.com/jhunt/go-ansi"
)

func main() {
    err := DoSomething()
    if err != nil {
        fmt.Printf("error: @R{%s}", err)
    }
}
```

`ansi.Fprintf`, `ansi.Sprintf` and `ansi.Errorf` behave similarly,
exporting the exact same call signature as their `fmt` bretheren, but
handling the ANSI color sequences for you.

Formatting Codes
----------------

The colorizing formatting codes all look like this:

    @ <color> { <text> }

![Colors in the Shell](colors.png)

(for the image-averse and search engines:)

```
  @k is Black         @K is Black (bold)
  @r is Red           @R is Red (bold)
  @g is Green         @G is Green (bold)
  @y is Yellow        @Y is Yellow (bold)
  @b is Blue          @B is Blue (bold)
  @m is Magenta       @M is Magenta (bold)
  @c is Cyan          @C is Cyan (bold)
  @w is White         @W is White (bold)
```

You can now also activate super-awesome RAINBOW mode with
`@*{...}`

To Colorize or Not To Colorize?
-------------------------------

Is that the question?

This library tries its hardest to determine whether or not
colorized sequences should be honored or removed outright, based
on the terminal-iness of the output medium.  For example, if
stdout is being redirected to a file, `ansi.Printf` will strip out
the color sequences altogether.

Sometimes this is impossible.  Specifically, for things like
`ansi.Errorf` and `ansi.Sprintf`, the library has no idea whether
or not the ultimate output stream even supports color code
sequences.  In those cases, you can check yourself, with
`ansi.CanColorize(io.Writer)` -- it returns true if the io.Writer
you passed it is hooked up to a terminal.  `ansi.ShouldColorize()`
is similar, except that it also returns true if
`ansi.ForceColor(true)` has been called.

Contributing
------------

1. Fork the repo
2. Write your code in a feature branch
3. Create a new Pull Request
