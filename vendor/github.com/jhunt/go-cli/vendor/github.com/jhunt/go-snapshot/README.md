snapshot
========

Sometimes you need to experiment.

```
package main

import (
  "fmt"
  "github.com/jhunt/go-snapshot"
)

type Thing struct {
  Name  string
  Value int
  On    bool
}

int main() {
  thing := Thing{
    Name:  "widget",
    Value: 4,
    On:    true,
  }

  sn, _ := snapshot.Take(&thing)

  ok := TrySomethingCrazy(&thing)
  if (ok) {
    fmt.Printf("something crazy worked!  %s = %d (on is %v)\n",
               thing.Name, thing,Value, thing.On)
    return
  }

  sn.Revert()

  ok = TrySomethingEvenCrazier(&thing)
  if (ok) {
    fmt.Printf("something EVEN CRAZIER worked!  %s = %d (on is %v)\n",
               thing.Name, thing,Value, thing.On)
    return
  }

  sn.Revert()
  fmt.Printf("nothing worked!  %s = %d (on is %v)\n",
             thing.Name, thing,Value, thing.On)
}
```

`snapshot` lets you take a point-in-time, deep-copy of an
arbitrary value, be it a string, boolean, number, struct, etc.,
and be able to return to that point in time at some point in the
future.

Contributing
============

This code is licensed MIT.  Enjoy.

If you find a bug, please raise a [Github Issue][issues] first,
before submitting a PR.

When you do work up a patch, keep in mind that we have a fairly
extensive test suite in `snapshot_test.go`.  I don't care _all that
much_ about code coverage, but we do have >90% C0 code coverage on
the current tests suite, and I'd like to keep it that way.

(That's not to say we've caught 90% of the bugs, but it's better
than nothin')

Happy Hacking!


[issues]: https://github.com/jhunt/go-snapshot/issues
