package iptables

import (
	"reflect"
	"testing"
)

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		rule     string
		expected Rule
	}{
		{
			rule:     `-A INPUT -s 8.8.8.8 -j DROP`,
			expected: Rule{RuleSpecifications: RuleSpecifications{Source: "8.8.8.8", Jump: "DROP"}, Chain: Chain{Name: "INPUT"}, Action: AppendAction},
		},
		{
			rule:     `-I OUTPUT -i eth0 -p tcp -s 8.8.8.8 -j DROP`,
			expected: Rule{RuleSpecifications: RuleSpecifications{InInterface: "eth0", Protocol: "tcp", Source: "8.8.8.8", Jump: "DROP"}, Chain: Chain{Name: "OUTPUT"}, Action: InsertAction},
		},
		{
			rule:     `-t filter -i lo -j ACCEPT -c 2 10`,
			expected: Rule{RuleSpecifications: RuleSpecifications{Jump: "ACCEPT", InInterface: "lo", SetCounters: "2 10"}, Table: "filter"},
		},
	}

	for i, test := range tests {
		rule, err := Unmarshal([]byte(test.rule))
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(rule, test.expected) {
			t.Errorf("unmarshal error, got \n%v\n, expected \n%v\n on test %d", rule, test.expected, i)
		}
	}
}
