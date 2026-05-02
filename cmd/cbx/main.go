package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		if ec, ok := err.(*exitCodeError); ok {
			os.Exit(ec.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
