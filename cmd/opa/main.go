package main

import (
	"fmt"
	"os"

	// register Built-in Functions from misscan
	_ "github.com/khulnasoft-lab/misscan/pkg/rego"
	"github.com/open-policy-agent/opa/cmd"
)

func main() {
	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}