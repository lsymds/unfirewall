package config

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lsymds/unfirewall/internal/unfirewall"
)

func TestMissingSourceTypeErrors(t *testing.T) {
	path, cleanup := createTestFile(t, `
		{
			"configuration": {
				"sources": {
					"test": {
						"a": "b"
					}
				}
			}
		}
	`)
	defer cleanup()

	if _, err := ParseRulesFromJsonFile(path); err == nil {
		t.Fatalf("no error returned")
	} else if !strings.Contains(err.Error(), "missing type") {
		t.Fatalf("expected missing type error, got: %s", err)
	}
}

func TestUnknownSourceTypeErrors(t *testing.T) {
	path, cleanup := createTestFile(t, `
		{
			"configuration": {
				"sources": {
					"test": {
						"type": "unknown"
					}
				}
			}
		}
	`)
	defer cleanup()

	if _, err := ParseRulesFromJsonFile(path); err == nil {
		t.Fatalf("no error returned")
	} else if !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("expected unknown source type error, got: %s", err)
	}
}

func TestMissingFirewallTypeErrors(t *testing.T) {
	path, cleanup := createTestFile(t, `
		{
			"configuration": {
				"destinations": {
					"test": {
					}
				}
			}
		}
	`)
	defer cleanup()

	if _, err := ParseRulesFromJsonFile(path); err == nil {
		t.Fatalf("no error returned")
	} else if !strings.Contains(err.Error(), "missing type") {
		t.Fatalf("expected missing type error, got: %s", err)
	}
}

func TestUnknownFirewallTypeErrors(t *testing.T) {
	path, cleanup := createTestFile(t, `
		{
			"configuration": {
				"destinations": {
					"test": {
						"type": "unknown"
					}
				}
			}
		}
	`)
	defer cleanup()

	if _, err := ParseRulesFromJsonFile(path); err == nil {
		t.Fatalf("no error returned")
	} else if !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("expected unknown firewall error, got: %s", err)
	}
}

func TestRuleWithUnknownDestinationErrors(t *testing.T) {
	path, cleanup := createTestFile(t, `
		{
			"rules": [
				{
					"destination": "unknown"
				}
			]
		}
	`)
	defer cleanup()

	if _, err := ParseRulesFromJsonFile(path); err == nil {
		t.Fatalf("no error returned")
	} else if !strings.Contains(err.Error(), "destination not configured") {
		t.Fatalf("expected destination not configured error, got: %s", err)
	}
}

func TestRuleWithUnknownSourceErrors(t *testing.T) {
	path, cleanup := createTestFile(t, `
		{
			"configuration": {
				"destinations": {
					"hetzner": {
						"type": "hetzner"
					}
				}
			},
			"rules": [
				{
					"destination": "hetzner",
					"source": "unknown"
				}
			]
		}
	`)
	defer cleanup()

	if _, err := ParseRulesFromJsonFile(path); err == nil {
		t.Fatalf("no error returned")
	} else if !strings.Contains(err.Error(), "source not configured") {
		t.Fatalf("expected source not configured error, got: %s", err)
	}
}

func TestRuleWithUnknownActionErrors(t *testing.T) {
	path, cleanup := createTestFile(t, `
		{
			"configuration": {
				"destinations": {
					"hetzner": {
						"type": "hetzner"
					}
				},
				"sources": {
					"cloudflare": {
						"type": "cloudflare"
					}
				}
			},
			"rules": [
				{
					"destination": "hetzner",
					"source": "cloudflare",
					"action": "unknown"
				}
			]
		}
	`)
	defer cleanup()

	if _, err := ParseRulesFromJsonFile(path); err == nil {
		t.Fatalf("no error returned")
	} else if !strings.Contains(err.Error(), "action") && !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected action invalid error, got: %s", err)
	}
}

func TestParsesRulesCorrectly(t *testing.T) {
	path, cleanup := createTestFile(t, `
		{
			"configuration": {
				"destinations": {
					"hetzner": {
						"type": "hetzner"
					}
				},
				"sources": {
					"cloudflare": {
						"type": "cloudflare"
					}
				}
			},
			"rules": [
				{
					"destination": "hetzner",
					"source": "cloudflare",
					"action": "allow",
					"port": 8080
				}
			]
		}
	`)
	defer cleanup()

	firewallRules, err := ParseRulesFromJsonFile(path)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if hetznerRule := ruleByName(t, firewallRules, "hetzner"); hetznerRule.Action != "allow" {
		t.Errorf("expected hetzner rule action to have action of allow, got: %s", hetznerRule.Action)
	} else if hetznerRule.Source.Type() != unfirewall.SourceCloudflare {
		t.Errorf("expected hetzner rule source type to be cloudflare, got: %s", hetznerRule.Source.Type())
	} else if hetznerRule.Port != 8080 {
		t.Errorf("expected hetzner rule port to be 8080, got: %v", hetznerRule.Port)
	} else if hetznerRule.Ports != nil {
		t.Errorf("expected hetzner rule ports to be empty, got: %v", hetznerRule.Ports)
	} else if hetznerRule.PortRange[0] != 0 || hetznerRule.PortRange[1] != 0 {
		t.Errorf("expected hetzner rule port range to be empty, got: %v", hetznerRule.PortRange)
	} else if hetznerRule.Interfaces != nil {
		t.Errorf("expected hetzner rule interfaces to be empty, got: %v", hetznerRule.Interfaces)
	}
}

func createTestFile(t *testing.T, contents string) (string, func()) {
	t.Helper()

	path := "test_" + uuid.NewString() + ".json"

	err := os.WriteFile(path, []byte(contents), os.FileMode(0700))
	if err != nil {
		t.Fatalf("creating test file: %s", err)
		return "", func() {}
	}

	return path, func() {
		err := os.Remove(path)
		if err != nil {
			t.Fatalf("removing test file: %s", err)
		}
	}
}

func ruleByName(t *testing.T, rules map[namedFirewall][]unfirewall.Rule, name string) unfirewall.Rule {
	t.Helper()

	for n, r := range rules {
		if n.Name == name {
			return r[0]
		}
	}

	t.Fatalf("firewall rule %s not found", name)
	return unfirewall.Rule{}
}
