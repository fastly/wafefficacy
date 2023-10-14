package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// GetNucleiVersion runs Nuclei --version, and returns the reported version.
func GetNucleiVersion() (string, error) {
	out, err := exec.Command("nuclei", "--version").CombinedOutput()
	if err != nil {
		return "", err
	}
	// TODO: use a capture group for the version instead
	versionRegex := regexp.MustCompile(`(?s)^.*Version: `)
	buf := string(out)
	nucleiVersion := versionRegex.ReplaceAllString(buf, "")
	return nucleiVersion, nil
}

// RunNuclei runs Nuclei with the given config, and returns a stream of its output.
func RunNuclei(config string, target string, templateDir string, verbose bool) (r io.Reader, err error) {
	args := []string{
		"-duc",
		"-ud", templateDir,
		"-config", config,
		"-u", target,
	}
	if verbose {
		// TODO: figure out where the verbose output goes... probably stderr, which we don't capture
		args = append(args, "-v")
	}
	cmd := exec.Command("nuclei", args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return r, err
	}

	return &out, err
}

// NucleiResults holds the results of a Nuclei run.
type NucleiResults struct {
	blockedResponse string
	attackTypes     []string
	results         []ScanResult
}

// ReadResults takes the stream of output from RunNuclei and a few other arguments, and returns a NucleiResults.
func ReadResults(nucleiOutput io.Reader, blockedResponse string, attackTypes []string) (nr NucleiResults, err error) {
	nr.blockedResponse = blockedResponse
	nr.attackTypes = attackTypes
	nr.results, err = readJSON(nucleiOutput)
	return nr, err
}

// ScanResult is the set of fields of the nuclei json output we care about
type ScanResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Author      []string `json:"author"`
		Tags        []string `json:"tags"`
		Description string   `json:"description"`
	} `json:"info"`
	Type     string `json:"type"`
	Request  string `json:"request"`
	Response string `json:"response"`
	Curl     string `json:"curl-command"`
}

// readJSON reads nuclei's output and sorts it so the json output can be compared with 'diff', such that identical results show no output
func readJSON(results io.Reader) (w []ScanResult, err error) {
	scanner := bufio.NewScanner(results)
	for scanner.Scan() {
		var scanResult ScanResult
		err := json.Unmarshal([]byte(scanner.Text()), &scanResult)
		if err != nil {
			return nil, err
		}
		w = append(w, scanResult)
	}
	sort.Slice(w, func(i, j int) bool {
		if w[i].TemplateID != w[j].TemplateID {
			return w[i].TemplateID < w[j].TemplateID
		}
		return w[i].Request < w[j].Request
	})

	return w, err
}

func (nr *NucleiResults) isBlocked(response string) bool {
	return strings.Contains(response, nr.blockedResponse)
}

func (nr *NucleiResults) truePositivesFalseNegatives(attackType string) (truePositives, falseNegatives int) {
	for _, result := range nr.results {
		if result.TemplateID == attackType+"-true-positive" {
			if nr.isBlocked(result.Response) {
				truePositives += 1
			} else {
				falseNegatives += 1
			}
		}
	}
	return truePositives, falseNegatives
}

func (nr *NucleiResults) trueNegativesFalsePositives(attackType string) (trueNegatives, falsePositives int) {
	for _, result := range nr.results {
		if result.TemplateID == attackType+"-false-positive" {
			if nr.isBlocked(result.Response) {
				falsePositives += 1
			} else {
				trueNegatives += 1
			}
		}
	}
	return trueNegatives, falsePositives
}

// PrintScore calculates the score, both overall and by attack type, and prints it to stdout.
func (nr *NucleiResults) PrintScore() {
	truePositives := 0
	falseNegatives := 0
	trueNegatives := 0
	falsePositives := 0
	efficacyScores := make(map[string]float64)

	for _, attackType := range nr.attackTypes {
		tp, fn := nr.truePositivesFalseNegatives(attackType)
		tn, fp := nr.trueNegativesFalsePositives(attackType)
		truePositives += tp
		falseNegatives += fn
		trueNegatives += tn
		falsePositives += fp
		fmt.Println("-------------" + strings.ToUpper(attackType) + "-------------")
		fmt.Println("True Positives", tp)
		fmt.Println("False Negatives", fn)
		fmt.Println("True Negatives", tn)
		fmt.Println("False Positives", fp)
		sensitivity := float64(tp) / float64(tp+fn)
		specificity := float64(tn) / float64(tn+fp)
		balanced_accuracy := (sensitivity + specificity) / 2
		efficacyScore := balanced_accuracy * 100
		efficacyScores[attackType] = efficacyScore
		fmt.Printf("Efficacy %.3f\n", efficacyScore)
	}

	fmt.Println("------------- WAF Efficacy -------------")
	total := 0.0
	for _, v := range efficacyScores {
		total += v
	}
	efficacyScore := total / float64(len(efficacyScores))
	fmt.Printf("Overall efficacy: %.3f\n", efficacyScore)
}

// PrintJSONResults formats the results as a subset of Nuclei's own JSON output, but sorted and diffable, and saves them in a timestamped file.
func (nr *NucleiResults) PrintJSONResults() error {
	// TODO: put it in the right directory/file
	w, err := os.Create("data.json")
	if err != nil {
		return err
	}
	defer w.Close()

	for _, result := range nr.results {
		b, err := json.Marshal(result)
		if err != nil {
			return err
		}
		line := fmt.Sprintln(string(b))
		_, err = w.WriteString(line)
		if err != nil {
			return err
		}
	}
	return nil
}
