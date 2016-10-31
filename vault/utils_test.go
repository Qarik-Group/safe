package vault

import "testing"

func TestParsePath(t *testing.T) {
	for _, test := range []struct {
		path      string //The full path to run through the parse function
		expSecret string //What is expected to be left of the colon
		expKey    string //What is expected to be right of the colon
	}{
		//-----TEST CASES GO HERE-----
		// { "path to parse", "expected secret", "expected key" }
		{"just/a/secret", "just/a/secret", ""},
		{"secret/with/colon:", "secret/with/colon", ""},
		{":", "", ""},
		{"a:", "a", ""},
		{"", "", ""},
		{"secret/and:key", "secret/and", "key"},
		{":justakey", "", "justakey"},
		{"secretwithcolon://127.0.0.1:", "secretwithcolon://127.0.0.1", ""},
		{"secretwithcolons://127.0.0.1:8500:", "secretwithcolons://127.0.0.1:8500", ""},
		{"secretwithcolons://127.0.0.1:8500:andkey", "secretwithcolons://127.0.0.1:8500", "andkey"},
	} {
		secret, key := ParsePath(test.path)
		if secret != test.expSecret || key != test.expKey {
			t.Errorf(`Parsing '%s':
			Expected:
				Secret: '%s'
				Key: '%s'
			Actual:
			 	Secret: '%s'
				Key: '%s'`, test.path, test.expSecret, test.expKey, secret, key)
		}
	}
}
