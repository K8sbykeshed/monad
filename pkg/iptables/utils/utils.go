package utils

import (
	"errors"
	"reflect"
	"strconv"
)

// LengthTag parses the length from the struct tag as an int
func LengthTag(key reflect.StructTag) (int, error) {
	length := 1
	lengthStr := key.Get("length")
	if lengthStr == "" || lengthStr == "1" {
		return length, nil
	}
	return strconv.Atoi(lengthStr)
}

// AssignValue assigns b to value val
func AssignValue(b []byte, val reflect.Value) error {
	if !val.CanSet() {
		return errors.New("cannot set struct field")
	}

	switch val.Kind().String() {
	case "string":
		val.SetString(string(b))
	case "int":
		i, err := strconv.Atoi(string(b))
		if err != nil {
			return err
		}
		val.SetInt(int64(i))
	default:
		return errors.New("unsupported field type")
	}
	return nil
}
