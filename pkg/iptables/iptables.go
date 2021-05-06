package iptables

import (
	"bytes"
	"github.com/K8sbykeshed/net-utils/pkg/iptables/utils"
	"reflect"
)

// Unmarshal converts a single line from ListRules into a Rule
func Unmarshal(data []byte) (Rule, error) {
	var rule Rule
	ruleValue := reflect.ValueOf(&rule).Elem()

	line := bytes.Split(data, []byte(" "))
	line = rule.handleAction(line)

	type valSet struct {
		key   reflect.StructTag
		value reflect.Value
	}
	var vals []valSet

	for i := 0; i < ruleValue.NumField(); i++ {
		vals = append(vals, valSet{ruleValue.Type().Field(i).Tag, ruleValue.Field(i)})
	}

Outer:
	for {
		if len(vals) == 0 {
			break
		}
		current := vals[0]
		vals = vals[1:]

		// kind is struct, assign fields to vals pool
		if current.value.Kind() == reflect.Struct {
			for i := 0; i < current.value.NumField(); i++ {
				vals = append(vals, valSet{
					current.value.Type().Field(i).Tag,
					current.value.Field(i),
				})
			}
			continue
		}

		if current.key.Get("short") == "-" || current.key.Get("short") == "" {
			continue
		}

		// assign
		for index := range line {
			if index+1 >= len(line) {
				break
			}

			// arg flag matches struct tag
			if bytes.Contains(line[index], []byte("-")) && current.key.Get("short") == string(bytes.Trim(line[index], "-")) {
				// array args - pass as space-separated length
				length, err := utils.LengthTag(current.key)
				if err != nil {
					return rule, err
				}
				var value []byte
				for j := index + 1; j <= index+length; j++ {
					value = append(value, line[j]...)
					value = append(value, []byte(" ")...)
				}
				utils.AssignValue(bytes.TrimSpace(value), current.value)
				continue Outer
			}
		}
	}
	return rule, nil
}
