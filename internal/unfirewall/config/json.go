package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/lsymds/unfirewall/internal/unfirewall"
	"github.com/lsymds/unfirewall/internal/unfirewall/firewalls/hetzner"
	"github.com/lsymds/unfirewall/internal/unfirewall/sources/cloudflare"
)

type jsonRuleSet struct {
	Configuration jsonConfiguration `json:"configuration"`
	Rules         []jsonRule        `json:"rules"`
}

type jsonConfiguration struct {
	Sources      map[string]map[string]interface{} `json:"sources"`
	Destinations map[string]map[string]interface{} `json:"destinations"`
}

type jsonRule struct {
	Action      string    `json:"action"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Port        uint16    `json:"port"`
	Ports       []uint16  `json:"ports"`
	PortRange   [2]uint16 `json:"port_range"`
	Interfaces  []string  `json:"interfaces"`
}

type namedFirewall struct {
	Name     string
	Firewall unfirewall.Firewall
}

// ParseRulesFromJsonFile reads the given JSON file and returns a map consisting of the destination firewall and
// rules to apply.
func ParseRulesFromJsonFile(path string) (map[namedFirewall][]unfirewall.Rule, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ruleset jsonRuleSet

	err = json.Unmarshal(contents, &ruleset)
	if err != nil {
		return nil, err
	}

	sources, err := createSourcesFromConfiguration(ruleset.Configuration)
	if err != nil {
		return nil, err
	}

	firewalls, err := createFirewallsFromConfiguration(ruleset.Configuration)
	if err != nil {
		return nil, err
	}

	return createRulesFromConfiguration(sources, firewalls, ruleset.Rules)
}

func createSourcesFromConfiguration(jsonConfiguration jsonConfiguration) (map[string]unfirewall.Source, error) {
	sources := make(map[string]unfirewall.Source, 0)

	for configurationSourceName, configurationSource := range jsonConfiguration.Sources {
		sourceName := strings.ToLower(configurationSourceName)

		var source unfirewall.Source
		var err error

		sourceType, ok := configurationSource["type"]
		if !ok {
			return nil, fmt.Errorf("source %s: missing type", sourceName)
		}

		// create each source, extracting any additional relevant properties from the JSON
		switch strings.ToLower(sourceType.(string)) {
		case string(unfirewall.SourceCloudflare):
			source, err = cloudflare.New()
			if err != nil {
				return nil, fmt.Errorf("source %s: %w", sourceName, err)
			}
		default:
			return nil, fmt.Errorf("source %s: unknown type", sourceType)
		}

		sources[sourceName] = source
	}

	return sources, nil
}

func createFirewallsFromConfiguration(jsonConfiguration jsonConfiguration) (map[string]unfirewall.Firewall, error) {
	firewalls := make(map[string]unfirewall.Firewall, 0)

	for configurationFirewallName, configurationFirewall := range jsonConfiguration.Destinations {
		firewallName := strings.ToLower(configurationFirewallName)

		var firewall unfirewall.Firewall
		var err error

		firewallType, ok := configurationFirewall["type"]
		if !ok {
			return nil, fmt.Errorf("firewall %s: missing type", firewallName)
		}

		// create each firewall, extracting any additional relevant properties from the JSON
		switch strings.ToLower(firewallType.(string)) {
		case string(unfirewall.FirewallHetzner):
			firewall, err = hetzner.New()
			if err != nil {
				return nil, fmt.Errorf("firewall %s: %w", firewallName, err)
			}
		default:
			return nil, fmt.Errorf("firewall %s: unknown type", firewallName)
		}

		firewalls[firewallName] = firewall
	}

	return firewalls, nil
}

func createRulesFromConfiguration(
	sources map[string]unfirewall.Source,
	firewalls map[string]unfirewall.Firewall,
	jsonRules []jsonRule,
) (map[namedFirewall][]unfirewall.Rule, error) {
	rules := make(map[namedFirewall][]unfirewall.Rule, 0)

	for i, configurationRule := range jsonRules {
		firewallName := strings.ToLower(configurationRule.Destination)
		firewall, ok := firewalls[firewallName]
		if !ok {
			return nil, fmt.Errorf("rule index %v: destination not configured", i)
		}

		sourceName := strings.ToLower(configurationRule.Source)
		source, ok := sources[sourceName]
		if !ok {
			return nil, fmt.Errorf("rule index %v: source not configured", i)
		}

		namedFirewall := namedFirewall{Name: firewallName, Firewall: firewall}

		// create the map entry for the firewall if it doesn't exist already
		if _, ok := rules[namedFirewall]; !ok {
			rules[namedFirewall] = make([]unfirewall.Rule, 0)
		}

		// parse all other rule values and assign them to a rule
		var action unfirewall.Action
		switch strings.ToLower(configurationRule.Action) {
		case string(unfirewall.ActionAllow):
			action = unfirewall.ActionAllow
		case string(unfirewall.ActionDeny):
			action = unfirewall.ActionDeny
		default:
			return nil, fmt.Errorf("rule index %v: action %s invalid", i, configurationRule.Action)
		}

		rule := unfirewall.Rule{
			Action:     action,
			Source:     source,
			Port:       configurationRule.Port,
			Ports:      configurationRule.Ports,
			PortRange:  configurationRule.PortRange,
			Interfaces: configurationRule.Interfaces,
		}

		rules[namedFirewall] = append(rules[namedFirewall], rule)
	}

	return rules, nil
}
