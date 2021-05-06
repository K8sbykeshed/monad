package iptables

type Option string

type Chain struct {
	Name    string
	Table   Table
	Options []Option
	Target  string
}
