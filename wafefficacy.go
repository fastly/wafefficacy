// WAFefficacy - tool to measure balanced accuracy of a WAF
// Copyright 2021-2025, Fastly

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/mattn/go-isatty"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// RunNuclei runs Nuclei with the given config, and returns results.
func RunNuclei(target string, templateDir string, blockedResponses []string, attackTypes, headers []string, suffix string, concurrency, retries, timeout int, nodates bool, verbose bool) (nr NucleiResults, err error) {
	nr.attackTypes = attackTypes
	nr.blockedResponses = blockedResponses
	nr.suffix = suffix
	nr.target = target

	// Add options to those in the config file
	config.DefaultConfig.DisableUpdateCheck()
	config.DefaultConfig.SetTemplatesDir(templateDir)
	nuc, err := nuclei.NewNucleiEngine(
		nuclei.WithConcurrency(nuclei.Concurrency{
			HeadlessHostConcurrency:       1,
			HeadlessTemplateConcurrency:   1,
			HostConcurrency:               1,
			JavascriptTemplateConcurrency: 1,
			ProbeConcurrency:              1,
			TemplateConcurrency:           concurrency,
			TemplatePayloadConcurrency:    1,
		}),
		nuclei.WithNetworkConfig(nuclei.NetworkConfig{
			Retries: retries,
			Timeout: timeout,
		}),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{
			Verbose:       verbose,
			Silent:        false,
			Debug:         verbose,
			DebugRequest:  verbose,
			DebugResponse: verbose,
			ShowVarDump:   verbose,
		}),
		nuclei.WithHeaders(headers),
		nuclei.WithVars([]string{"suffix=" + suffix}),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Severity: "info", Tags: attackTypes}),
	)
	if err != nil {
		return nr, err
	}
	defer nuc.Close()
	nuc.LoadTargets([]string{target}, false)
	cb := func(re *output.ResultEvent) {
		if verbose {
			rlen := len(re.Response)
			if rlen > 10000 {
				rlen = 10000
			}
			fmt.Printf("\n%s: blocked %v; penetrated %v\n%s\n%s\n",
				re.TemplateID, nr.isBlocked(re.Response), nr.isPenetrated(re.Response), re.CURLCommand, re.Response[:rlen])
		}
		if nodates {
			re.Response = sanitizeDates(re.Response)
			re.Request = sanitizeDates(re.Request)
		}
		nr.E = append(nr.E, *re)
		if isatty.IsTerminal(os.Stderr.Fd()) && len(nr.E)%10 == 0 {
			fmt.Fprintf(os.Stderr, "\r%d ", len(nr.E))
		}
	}
	ctx := context.TODO()
	fmt.Fprintf(os.Stderr, "\n")
	err = nuc.ExecuteCallbackWithCtx(ctx, cb)
	fmt.Fprintf(os.Stderr, "\n")
	if err != nil {
		return nr, err
	}

	sort.Slice(nr.E, func(i, j int) bool {
		if nr.E[i].TemplateID != nr.E[j].TemplateID {
			return nr.E[i].TemplateID < nr.E[j].TemplateID
		}
		m1, p1 := nr.extractPayload(nr.E[i].Request)
		m2, p2 := nr.extractPayload(nr.E[j].Request)
		if p1 == p2 {
			return m1 < m2
		}
		return p1 < p2
	})

	nr.CalculateScore()

	return nr, nil
}

// Date: Fri, 09 May 2025 03:35:19 GMT\r\n
var reDate = regexp.MustCompile(`Date: ..., \d\d ... \d\d\d\d \d\d:\d\d:\d\d ...`)

// sanitizeDates replaces all dates with the epoch
// Useful for making the diff of two runs more meaningful
func sanitizeDates(s string) string {
	// $ date -u -R -r 0
	// Thu, 01 Jan 1970 00:00:00 +0000
	return reDate.ReplaceAllString(s, "Date: Thu, 01 Jan 1970 00:00:00 GMT")
}

func (nr *NucleiResults) getCondensed() (s NucleiResultsSubset) {
	s.target = nr.target
	s.attackTypes = nr.attackTypes
	s.blockedResponses = nr.blockedResponses
	s.AvgScore = nr.AvgScore
	s.Scores = nr.Scores
	for _, e := range nr.E {
		// Only export the failed tests for now
		blocked := nr.isBlocked(e.Response)
		if (strings.HasSuffix(e.TemplateID, "-false-positive") && blocked) || (strings.HasSuffix(e.TemplateID, "-true-positive") && !blocked) {
			s.E = append(s.E, nr.CondenseResultEvent(e))
		}
	}
	return s
}

func (nr *NucleiResults) CondenseResultEvent(i output.ResultEvent) (s ResultEventSubset) {
	s.TemplateID = i.TemplateID
	s.Info = i.Info
	s.Request = i.Request
	s.Response = i.Response
	s.CURLCommand = i.CURLCommand
	s.Method, s.Payload = nr.extractPayload(i.Request)
	return s
}

func (s *Score) CalculateEfficacy() {
	sensitivity := 0.0
	if s.tp > 0 {
		sensitivity = float64(s.tp) / float64(s.tp+s.fn)
	}
	specificity := 0.0
	if s.tn > 0 {
		specificity = float64(s.tn) / float64(s.tn+s.fp)
	}
	balanced_accuracy := (sensitivity + specificity) / 2
	s.Efficacy = float32(balanced_accuracy * 100)
}

// CalculateScore calculates and saves the score in the result struct
func (nr *NucleiResults) CalculateScore() {
	nr.Scores = make(map[string]Score)

	for _, attackType := range nr.attackTypes {
		var s Score
		s.tp, s.fn = nr.truePositivesFalseNegatives(attackType)
		s.tn, s.fp = nr.trueNegativesFalsePositives(attackType)
		(&s).CalculateEfficacy()
		nr.Scores[attackType] = s
	}
	avg := 0.0
	for _, s := range nr.Scores {
		// Update global counts because report wants them
		nr.overall.tp += s.tp
		nr.overall.fp += s.fp
		nr.overall.tn += s.tn
		nr.overall.fn += s.fn
		avg += float64(s.Efficacy)
	}
	nr.overall.CalculateEfficacy()                       // sensitive to test case misbalance; interesting but probably not useful.
	nr.AvgScore = float32(avg / float64(len(nr.Scores))) // more balanced than nr.overall.Efficacy
}

// PrintResultsText prints scores, both overall and by attack type, to the given Writer
func (nr *NucleiResults) PrintResultsText(w io.Writer, details, nonum bool) (err error) {
	_, err = fmt.Fprintf(w, "WAFefficacy results for %s\n\n", nr.target)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "overall balanced accuracy: %.3f%%\n", nr.AvgScore)
	for _, attackType := range nr.attackTypes {
		AttackType := strings.ToUpper(attackType)
		s := nr.Scores[attackType]
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "%-9s                          blocked            not blocked\n", "")
		fmt.Fprintf(w, "%-9s attacks:    true positives: %4d  false negatives: %4d\n", AttackType, s.tp, s.fn)
		fmt.Fprintf(w, "%-9s innocent:  false positives: %4d   true negatives: %4d\n", AttackType, s.fp, s.tn)
		fmt.Fprintf(w, "%-9s balanced accuracy %.3f%%\n", AttackType, s.Efficacy)
	}

	if !details {
		return nil
	}

	fmt.Fprintf(w, "\n%d innocent requests were blocked (aka false positives):\n", nr.overall.fp)
	i := 1
	for _, attackType := range nr.attackTypes {
		AttackType := strings.ToUpper(attackType)
		if nr.Scores[attackType].fp > 0 {
			for _, result := range nr.E {
				if result.TemplateID == attackType+"-false-positive" && nr.isBlocked(result.Response) {
					m, p := nr.extractPayload(result.Request)
					if nonum {
						fmt.Fprintf(w, " %-9s  %7s  %s\n", AttackType, m, p)
					} else {
						fmt.Fprintf(w, " %3d  %-9s  %7s  %s\n", i, AttackType, m, p)
					}
					i++
				}
			}
		}
	}

	fmt.Fprintf(w, "\n%d malicious requests were not blocked (aka false negatives):\n", nr.overall.fn)
	i = 1
	for _, attackType := range nr.attackTypes {
		AttackType := strings.ToUpper(attackType)
		if nr.Scores[attackType].fn > 0 {
			for _, result := range nr.E {
				if result.TemplateID == attackType+"-true-positive" && !nr.isBlocked(result.Response) {
					m, p := nr.extractPayload(result.Request)
					if nonum {
						fmt.Fprintf(w, " %-9s  %7s  %s\n", AttackType, m, p)
					} else {
						fmt.Fprintf(w, " %3d  %-9s  %7s  %s\n", i, AttackType, m, p)
					}
					i++
				}
			}
		}
	}
	return nil
}

// PrintResultsJSON prints scores, both overall and by attack type, to the given Writer
func (nr *NucleiResults) PrintResultsJSON(w io.Writer, details bool) (err error) {
	if details {
		report := nr.getCondensed()
		b, err := json.MarshalIndent(report, "", " ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "%s\n", string(b))
		return err
	}

	b, err := json.Marshal(nr.Report)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", string(b))

	return err
}

func (nr *NucleiResults) truePositivesFalseNegatives(attackType string) (truePositives, falseNegatives int) {
	for _, result := range nr.E {
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
	for _, result := range nr.E {
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

// isBlocked returns true if the attack was blocked by a WAF.
//
// Running real attacks against a very vulnerable origin should yield isPenetrated;
// running them against a waf should yield isBlocked.
//
// Used to compute waf efficacy.
func (nr *NucleiResults) isBlocked(response string) bool {
	for _, r := range nr.blockedResponses {
		if strings.Contains(response, "HTTP/1.1 "+r) {
			return true
		}
	}
	return false
}

// isPenetrated returns true if the attack succeeded on a real system (e.g. dvwa).
//
// Running real attacks against a very vulnerable origin should yield isPenetrated;
// running them against a waf should yield isBlocked.
//
// Not used to compute waf efficacy,
// since our payloads are all labelled as true (attack) or false (benign),
// but could eventually be used to check whether the labels are correct,
// or to find the subset of the attacks an origin is vulnerable to.
//
// For now it's just used as a curio, to decorate the log when verbose output is specified.
func (nr *NucleiResults) isPenetrated(response string) bool {
	telltales := []string{
		// TODO: complete this list
		"uid=0(root)",       // output of 'id'
		"(www-data)",        // output of 'id'
		"FLAGFLAG",          // traversal
		"eth0:",             // ifconfig
		"root:",             // cat /etc/passwd
		"root root",         // ls -l
		"www-data www-data", // ls -l
	}

	// TODO: use headless support to detect XSS
	// TODO: detect more non-XSS attacks with a telltale
	for _, tell := range telltales {
		if strings.Contains(response, tell) {
			return true
		}
	}
	return false
}

// extractPayload attempts to retrieve the payload handed to the nuclei template.
// This is kind of backwards... but I'm not sure how to do it right.
// nuclei doesn't quite make this easy; we'd really like to
// retrieve the payload variable used by the template instead of this.
func (nr *NucleiResults) extractPayload(raw string) (method, payload string) {
	reqReader := bufio.NewReader(strings.NewReader(raw))
	req, err := http.ReadRequest(reqReader)
	if err != nil {
		return "?", raw // return something rather than panic?
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return req.Method, raw // return something rather than panic?
	}
	query := string(body)
	if len(query) == 0 {
		url := req.URL.String()
		parts := strings.Split(url, "?")
		if len(parts) < 2 {
			query = url
		} else {
			query = parts[1]
		}
	}
	// Now skip the first assignment
	offset := strings.Index(query, "=")
	encPayload := query[offset+1:]
	// And reverse the URL encoding applied by the nuclei template.
	// This is now QueryEscape; in the past, it was PathEscape.  See https://github.com/projectdiscovery/nuclei/pull/980/files
	// Nuclei is probably wrong here!
	payload, err = url.QueryUnescape(encPayload)
	if err != nil {
		payload = encPayload // return something rather than panic?!
	}
	// Then remove any suffix we added
	payload, _ = strings.CutSuffix(payload, nr.suffix)
	return req.Method, payload
}

// NucleiResults holds the results of a Nuclei run
type NucleiResults struct {
	Report
	E []output.ResultEvent
}

// NucleiResultsSubset holds just the interesting part of the results of a Nuclei run
type NucleiResultsSubset struct {
	Report
	E []ResultEventSubset // just the failures
}

type Report struct {
	target           string
	suffix           string
	attackTypes      []string
	blockedResponses []string
	AvgScore         float32 `json:"overall"` // avoid noise in low bits of float64
	overall          Score
	Scores           map[string]Score
}

// ResultEventSubset is the set of fields of ResultEvent we want in our detailed report
type ResultEventSubset struct {
	TemplateID  string     `json:"template-id"`
	Info        model.Info `json:"info,inline"`
	Method      string     `json:"method"`  // nuclei doesn't provide this?!
	Payload     string     `json:"payload"` // nuclei doesn't provide this?!
	Request     string     `json:"request"`
	Response    string     `json:"response"`
	CURLCommand string     `json:"curl-command"`
}

type Score struct {
	tp, tn, fp, fn int
	Efficacy       float32
}
