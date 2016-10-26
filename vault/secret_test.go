package vault

import "testing"

func TestSingleValue(t *testing.T) {
	for _, test := range []struct {
		data      map[string]string //data to put in the secret object
		expected  string            //string expected to be returned. ignored if shouldErr is true
		shouldErr bool              //true if the err returned should not be equal to nil
	}{
		//-----TEST CASES GO HERE-----
		{map[string]string{"key": "value"}, "value", false},
		{map[string]string{"key": "value", "other": "value"}, "", true},
		{map[string]string{"": "value"}, "value", false},
		{map[string]string{}, "", true},
		{nil, "", true},
	} {
		//TEST CODE
		value, err := (&Secret{data: test.data}).SingleValue()
		if !test.shouldErr {
			if err != nil {
				t.Errorf("SingleValue should not have erred but did \n\t data contents: %+v", test.data)
			} else if value != test.expected {
				t.Errorf("SingleValue:\n\t expected: %s\n\t actual: %s\n", test.expected, value)
			}
		} else if test.shouldErr && err == nil {
			t.Errorf("SingleValue should have erred but did not\n\t data contents: %+v", test.data)
		}
	}
}
