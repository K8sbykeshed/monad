package iptables

type Table string

const (
	Filter Table = "filter"
	Nat    Table = "nat"
	Mangle Table = "mangle"
	Raw    Table = "raw"
)
