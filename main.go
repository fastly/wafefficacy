package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{Use: "wafefficacy"}

	var target string
	var verbose bool
	var templateDir string
	var config string
	var blockedResponse string

	attackTypes := []string{"cmdexe", "sqli", "traversal", "xss"}

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run WAF Efficacy Tests",
		Run: func(cmd *cobra.Command, args []string) {
			if target == "" {
				fmt.Println("Error: must specify target URL/host to scan")
				os.Exit(1)
			}

			nucleiVersion, err := GetNucleiVersion()
			if err != nil {
				fmt.Println("Can't find nuclei", err)
				os.Exit(1)
			}

			fmt.Println("Running efficacy tests using Nuclei version", nucleiVersion)
			nucleiOutput, err := RunNuclei(config, target, templateDir, verbose)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			nr, err := ReadResults(nucleiOutput, blockedResponse, attackTypes)
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
		},
	}

	cmd.PersistentFlags().StringVarP(&target, "target", "u", "", "target URL/host to scan")
	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose")
	cmd.PersistentFlags().StringVarP(&templateDir, "template-dir", "t", "nuclei-templates", "path to the nuclei template directory")
	cmd.PersistentFlags().StringVarP(&config, "config", "c", "config.yaml", "path to the nuclei configuration file")
	cmd.PersistentFlags().StringVarP(&blockedResponse, "response", "r", "406 Not Acceptable", "WAF response for blocked requests")
	cmd.PersistentFlags().StringSliceVar(&attackTypes, "attacks", attackTypes, "list of attack types")

	rootCmd.AddCommand(cmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
