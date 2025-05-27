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

	"github.com/fastly/wafefficacy/lib"

	"github.com/mattn/go-isatty"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// RunNuclei runs Nuclei with the given config, and returns results.
func RunNuclei(target, wafname string, templateDir string, blockedResponses []string, attackTypes, headers []string, suffix string, concurrency, retries, timeout int, nodates bool, verbose bool) (nr NucleiResults, err error) {
	nr.AttackTypes = attackTypes
	nr.BlockedResponses = blockedResponses
	nr.Suffix = suffix
	nr.Target = target
	nr.WAFName = wafname

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
		if isatty.IsTerminal(os.Stderr.Fd()) && len(nr.E)%100 == 0 {
			fmt.Fprintf(os.Stderr, "\r%6d ", len(nr.E))
		}
	}
	ctx := context.TODO()
	err = nuc.ExecuteCallbackWithCtx(ctx, cb)
	fmt.Fprintf(os.Stderr, "\n%6d responses received from waf %s at %s\n", len(nr.E), nr.WAFName, nr.Target)
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

func (nr *NucleiResults) getCondensed() (s lib.NucleiResultsSubset) {
	s.Target = nr.Target
	s.WAFName = nr.WAFName
	s.AttackTypes = nr.AttackTypes
	s.BlockedResponses = nr.BlockedResponses
	s.AvgScore = nr.AvgScore
	s.Overall = nr.Overall
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

func (nr *NucleiResults) CondenseResultEvent(i output.ResultEvent) (s lib.ResultEventSubset) {
	s.TemplateID = i.TemplateID
	s.Request = i.Request
	s.Response = i.Response
	s.CURLCommand = i.CURLCommand
	s.Method, s.Payload = nr.extractPayload(i.Request)
	return s
}

// CalculateScore calculates and saves the score in the result struct
func (nr *NucleiResults) CalculateScore() {
	nr.Scores = make(map[string]lib.Score)

	for _, attackType := range nr.AttackTypes {
		var s lib.Score
		s.Tp, s.Fn = nr.truePositivesFalseNegatives(attackType)
		s.Tn, s.Fp = nr.trueNegativesFalsePositives(attackType)
		(&s).CalculateEfficacy()
		nr.Scores[attackType] = s
	}
	avg := 0.0
	for _, s := range nr.Scores {
		// Update global counts because report wants them
		nr.Overall.Tp += s.Tp
		nr.Overall.Fp += s.Fp
		nr.Overall.Tn += s.Tn
		nr.Overall.Fn += s.Fn
		avg += float64(s.Efficacy)
	}
	nr.Overall.CalculateEfficacy()
	nr.AvgScore = lib.RoundedFloat64(avg / float64(len(nr.Scores))) // like nr.Overall.Efficacy, but avoids bias from different sized attack type corpora?
}

// PrintResultsText prints scores, both overall and by attack type, to the given Writer
func (nr *NucleiResults) PrintResultsText(w io.Writer, details, nonum bool) (err error) {
	_, err = fmt.Fprintf(w, "WAFefficacy results for %s\n\n", nr.Target)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "overall balanced accuracy: %.3f%%\n", nr.AvgScore*100)
	for _, attackType := range nr.AttackTypes {
		AttackType := strings.ToUpper(attackType)
		s := nr.Scores[attackType]
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "%-9s                          blocked            not blocked\n", "")
		fmt.Fprintf(w, "%-9s attacks:    true positives: %4d  false negatives: %4d\n", AttackType, s.Tp, s.Fn)
		fmt.Fprintf(w, "%-9s innocent:  false positives: %4d   true negatives: %4d\n", AttackType, s.Fp, s.Tn)
		fmt.Fprintf(w, "%-9s balanced accuracy %.3f%%\n", AttackType, s.Efficacy*100)
	}

	if !details {
		return nil
	}

	fmt.Fprintf(w, "\n%d innocent requests were blocked (aka false positives):\n", nr.Overall.Fp)
	i := 1
	for _, attackType := range nr.AttackTypes {
		AttackType := strings.ToUpper(attackType)
		if nr.Scores[attackType].Fp > 0 {
			for _, result := range nr.E {
				if result.TemplateID == attackType+"-false-positive" && nr.isBlocked(result.Response) {
					m, p := nr.extractPayload(result.Request)
					if len(p) > 200 {
						p = p[:200] + "..."
					}
					if nonum {
						fmt.Fprintf(w, " %-9s  %7s  %q\n", AttackType, m, p)
					} else {
						fmt.Fprintf(w, " %3d  %-9s  %7s  %q\n", i, AttackType, m, p)
					}
					i++
				}
			}
		}
	}

	fmt.Fprintf(w, "\n%d malicious requests were not blocked (aka false negatives):\n", nr.Overall.Fn)
	i = 1
	for _, attackType := range nr.AttackTypes {
		AttackType := strings.ToUpper(attackType)
		if nr.Scores[attackType].Fn > 0 {
			for _, result := range nr.E {
				if result.TemplateID == attackType+"-true-positive" && !nr.isBlocked(result.Response) {
					m, p := nr.extractPayload(result.Request)
					if len(p) > 200 {
						p = p[:200] + "..."
					}
					if nonum {
						fmt.Fprintf(w, " %-9s  %7s  %q\n", AttackType, m, p)
					} else {
						fmt.Fprintf(w, " %3d  %-9s  %7s  %q\n", i, AttackType, m, p)
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
		return report.ToFile(w)
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
	for _, r := range nr.BlockedResponses {
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
	payload, _ = strings.CutSuffix(payload, nr.Suffix)
	return req.Method, payload
}

// NucleiResults holds the results of a Nuclei run
type NucleiResults struct {
	lib.Report
	E []output.ResultEvent
}
