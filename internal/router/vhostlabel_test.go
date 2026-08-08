package router

import "testing"

// TestValidateVhostLabel_AcceptsOnlyASingleUsableLabel walks what a caller may
// name a service. The rule has to agree with the whole-name check, because a
// label accepted here has a server name and a suffix appended and is then
// checked again: anything this let through that the second check refused would
// be a refusal the caller could not have predicted from what they typed.
func TestValidateVhostLabel_AcceptsOnlyASingleUsableLabel(t *testing.T) {
	ok := []string{"grafana", "web-1", "a", "x0", "0x", "a-b-c"}
	for _, l := range ok {
		if err := ValidateVhostLabel(l); err != nil {
			t.Errorf("ValidateVhostLabel(%q) refused a usable name: %v", l, err)
		}
		// The agreement that matters: appended to a server and suffix, it must
		// still be a name the table will accept.
		if err := ValidateVhostKey(l + ".server1.internal"); err != nil {
			t.Errorf("label %q was accepted but the whole name it builds was not: %v", l, err)
		}
	}

	bad := map[string]string{
		"":                "empty",
		"a.b":             "more than one label",
		"grafana.server1": "more than one label",
		"*":               "a pattern",
		"*.x":             "a pattern",
		"gra*na":          "a pattern",
		"Grafana":         "uppercase",
		"-web":            "leading dash",
		"web-":            "trailing dash",
		"web_1":           "underscore, which a hostname may not carry",
		"web 1":           "a space",
		"web:80":          "a port",
		"café":            "not an ASCII hostname label",
	}
	for l, why := range bad {
		if err := ValidateVhostLabel(l); err == nil {
			t.Errorf("ValidateVhostLabel(%q) accepted %s", l, why)
		}
	}
}
