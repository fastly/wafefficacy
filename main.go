package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	// Options with shorthand names (trying to keep same names as nuclei's)
	var target string
	var verbose bool

	// Options
	flag.StringVar(&target, "target", "", "target URL/host to scan")
	flag.StringVar(&target, "u", "", "target URL/host to scan (shorthand)")
	config := flag.String("config", "nuclei/config.yaml", "path to the nuclei configuration file")
	blockedResponse := flag.String("r", "406 Not Acceptable", "waf response for blocked requests")
	flag.BoolVar(&verbose, "verbose", false, "verbose")
	flag.BoolVar(&verbose, "v", false, "verbose (shorthand)")

	// TODO: make an option
	attackTypes := []string{"cmdexe", "sqli", "traversal", "xss"}

	flag.Parse()

	if target == "" {
		fmt.Printf("Error: must specify target url with --target or -u\n")
		os.Exit(1)
	}

	nucleiVersion, err := GetNucleiVersion()
	if err != nil {
		fmt.Println("Can't find nuclei", err)
		os.Exit(1)
	}

	fmt.Println("Running efficacy tests using Nuclei version", nucleiVersion)
	nucleiOutput, err := RunNuclei(*config, target, verbose)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	nr, err := ReadResults(nucleiOutput, *blockedResponse, attackTypes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	nr.PrintScore()

	err = nr.PrintJSONResults()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
