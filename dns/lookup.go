package dns

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

func Lookup(query string, server string) ([]string, error) {
	if !strings.HasSuffix(query, ".") {
		query += "." // has to be fully qualified
	}

	fmt.Printf("trying lookup of %s against %s\n", query, server)
	c := &dns.Client{}
	m := &dns.Msg{}
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = []dns.Question{dns.Question{query, dns.TypeA, dns.ClassINET}}

	l := make([]string, 0)
	in, _, err := c.Exchange(m, server+":53") // FIXME: is the :53 superfluous?
	if err != nil {
		return nil, err
	} else {
		for _, rr := range in.Answer {
			if a, ok := rr.(*dns.A); ok {
				l = append(l, a.A.String())
			} else {
				return nil, fmt.Errorf("Expecting only A records but got '%s' -- please open an issue on github.com/starkandwayne/safe", rr)
			}
		}
	}
	return l, nil
}
