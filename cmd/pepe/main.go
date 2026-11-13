package main

import (
	"fmt"
	"github.com/marccampbell/pepe/internal/cli"
	"os"
)

var version = "dev"

func main() {
	if err := cli.Run(os.Args[1:], version); err != nil {
		fmt.Fprintln(os.Stderr, "pepe:", err)
		os.Exit(1)
	}
}
