package main

import (
	"fmt"
	"github.com/K8sbykeshed/net-utils/pkg/iptables"
	"log"
)

func main() {
	var (
		err error
		rule iptables.Rule
	)

	cmd := []byte("-A INPUT -s 8.8.8.8 -j DROP")
	if rule, err = iptables.Unmarshal(cmd); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%+v\n", rule)
}
