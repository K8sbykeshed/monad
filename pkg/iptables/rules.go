package iptables

type Action string

const (
	InsertAction Action = "insert"
	AppendAction Action = "append"
	DeleteAction Action = "delete"
	PolicyAction Action = "policy"
)

type Rule struct {
	RuleNumber string `short:"_" long:"_"`
	Table      Table  `short:"t" long:"table"` // filter is default
	Chain      Chain  `short:"-" long:"-"`
	Action     Action `short:"-" long:"-"`

	RuleSpecifications RuleSpecifications `short:"-" long:"-"`
	MatchExtensions    MatchExtensions    `short:"-" long:"-"`
	TargetExtensions   TargetExtensions   `short:"-" long:"-"`
}

type RuleSpecifications struct {
	Protocol     string `short:"p" long:"protocol"`
	Source       string `short:"s" long:"source"`
	Destination  string `short:"d" long:"destination"`
	Jump         string `short:"j" long:"jump"` // Target
	Goto         string `short:"g" long:"goto"`
	InInterface  string `short:"i" long:"in-interface"`
	OutInterface string `short:"o" long:"out-interface"`
	Fragment     string `short:"f" long:"fragment"`
	Match        string `short:"m" long:"match"`
	SetCounters  string `short:"c" long:"set-counters" length:"2"`
}


// handleAction sets a rule's Action and Chain, if they are in the line input
func (r *Rule) handleAction(line [][]byte) [][]byte {
	if len(line) < 2 {
		return line
	}
	switch string(line[0]) {
	case "-I":
		r.Action = InsertAction
	case "-A":
		r.Action = AppendAction
	case "-D":
		r.Action = DeleteAction
	case "-P":
		r.Action = PolicyAction
	default:
		return line
	}
	r.Chain = Chain{Name: string(line[1])}
	return line[2:]
}
