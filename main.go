package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{Use: "wafefficacy"}

	var target string
	var templateDir string
	var verbose bool

	attackTypes := []string{"cmdexe", "sqli", "traversal", "xss"}
	blockedResponses := []string{"403", "406"}
	headers := []string{}
	suffix := ""
	outText := "-"
	outJSON := ""
	concurrency := 1
	nonum := false

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run WAF Efficacy Tests",
		Run: func(cmd *cobra.Command, args []string) {
			if target == "" {
				fmt.Println("Error: must specify target URL/host to scan")
				os.Exit(1)
			}
			nr, err := RunNuclei(target, templateDir, blockedResponses, attackTypes, headers, suffix, concurrency, verbose)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			switch outText {
			case "":
			case "-":
				nr.PrintResultsText(os.Stdout, true, nonum)
			default:
				f, err := os.Create(outText)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				defer f.Close()
				err = nr.PrintResultsText(f, true, nonum)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}

			switch outJSON {
			case "":
			case "-":
				nr.PrintResultsJSON(os.Stdout, true)
			default:
				f, err := os.Create(outJSON)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				defer f.Close()
				err = nr.PrintResultsJSON(f, true)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}
		},
	}

	cmd.PersistentFlags().StringSliceVar(&attackTypes, "attacks", attackTypes, "which attack types to run")
	cmd.PersistentFlags().StringSliceVarP(&blockedResponses, "response", "r", blockedResponses, "WAF responses for blocked requests")
	cmd.PersistentFlags().IntVarP(&concurrency, "concurrency", "c", concurrency, "concurrency")
	cmd.PersistentFlags().StringSliceVarP(&headers, "headers", "H", nil, "Add a header")
	cmd.PersistentFlags().StringVarP(&outJSON, "reportJson", "j", outJSON, "where to write json report; - for stdout")
	cmd.PersistentFlags().StringVarP(&outText, "report", "o", outText, "where to write text report; - for stdout")
	cmd.PersistentFlags().StringVarP(&suffix, "suffix", "", suffix, "extra get/post params, e.g. --suffix '&Submit=Submit'")
	cmd.PersistentFlags().StringVarP(&target, "url", "u", "", "target URL to scan")
	cmd.PersistentFlags().StringVarP(&templateDir, "template-dir", "t", "nuclei-templates", "path to the nuclei template directory")
	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose")
	cmd.PersistentFlags().BoolVarP(&nonum, "nonum", "n", false, "don't number detailed results")

	rootCmd.AddCommand(cmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
