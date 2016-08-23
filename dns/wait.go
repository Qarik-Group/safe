package dns

import (
	"time"
)

func HasRecordsFor(query string, servers []string) bool {
	for _, server := range servers {
		rr, err := Lookup(query, server)
		if err != nil {
			continue
		}
		return len(rr) != 0
	}
	return false
}

func WaitForChange(query string, current string, timeout int, servers []string) (string, bool) {
	agents := make([]chan int, len(servers))
	response := make(chan string, len(servers))

	for i, server := range servers {
		agents[i] = make(chan int, 0)
		go func(n int, in chan int, out chan string, have string) {
			for {
				select {
				case <-in:
					return
				default:
					break
				}

				rr, err := Lookup(query, server)
				if err != nil {
					return
				}

				got := ""
				if len(rr) > 0 {
					got = rr[0]
				}

				if got != have {
					out <- got
					<-in
					return
				}

				time.Sleep(250 * time.Millisecond)
			}
		}(i, agents[i], response, current)
	}

	t := time.NewTimer(time.Duration(timeout) * time.Second)

	select {
	case rr := <-response:
		for _, ch := range agents {
			ch <- 1 /* shut down the goroutine workers */
			close(ch)
		}
		return rr, true
	case <-t.C:
		for _, ch := range agents {
			ch <- 1 /* shut down the goroutine workers */
			close(ch)
		}
		return "", false
	}

	return "", false
}
