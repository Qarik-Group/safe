package vault

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

func Lookup(query string, server string) []string {

	if !strings.HasSuffix(server, ".") {
		server += "." // has to be fully qualified
	}

	c := &dns.Client{}
	m := &dns.Msg{}
	m.Id = dns.Id()
	m.RecursionDesired = false
	m.Question = []dns.Question{dns.Question{query, dns.TypeA, dns.ClassINET}}

	l := make([]string, 0)
	in, _, err := c.Exchange(m, server)
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
	return l
}

/*

safe cli
  - seal, unseal, status: will send to all to perform action
	- everything else: talks to dns to determine all nodes, picks active node before proceeding
  - update .saferc with current status
	- safe sync is a no-op -- just updates the rc.

steps:
  read rc
	contact dns
	get list of all nodes, including determining active node
	writes the info to rc
	proceed with command

The above will be the responsibility of the Apply.  Will take a cached:true argument to force not using dns (for commands like target and targets)

Libraries:
  vault/dns.go
	  - just lookup based on custom dns server
		- returns active vault,  all vaults
	vault/vault.go
	  - request function needs to be duplicate/split to requestToActive/requestToAll
	rc/config.go
	  - Apply to be updated








*/
