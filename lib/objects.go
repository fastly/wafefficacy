package lib

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// NucleiResultsSubset holds just the interesting part of the results of a Nuclei run
type NucleiResultsSubset struct {
	Report
	E []ResultEventSubset // just the failures
}

type Report struct {
	Target           string           `json:"target"`
	WAFName          string           `json:"wafname"`
	Suffix           string           `json:"suffix"`
	AttackTypes      []string         `json:"attacktypes"`
	BlockedResponses []string         `json:"blockedResponses"`
	AvgScore         RoundedFloat64   `json:"avgscore"`
	Overall          Score            `json:"overall"`
	Scores           map[string]Score `json:"scores"`
}

// ResultEventSubset is the set of fields of ResultEvent we want in our detailed report
type ResultEventSubset struct {
	TemplateID  string `json:"template-id"`
	Method      string `json:"method"`  // nuclei doesn't provide this?!
	Payload     string `json:"payload"` // nuclei doesn't provide this?!
	Request     string `json:"request"`
	Response    string `json:"response"`
	CURLCommand string `json:"curl-command"`
}

type Score struct {
	Tp, Tn, Fp, Fn int
	Sensitivity    RoundedFloat64
	Specificity    RoundedFloat64
	Efficacy       RoundedFloat64 // balanced accuracy
}

func (r *NucleiResultsSubset) ToFile(w io.Writer) error {
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", string(b))
	return err
}

func FromFile(reader io.Reader) (report NucleiResultsSubset, err error) {
	byteValue, _ := io.ReadAll(reader)
	err = json.Unmarshal(byteValue, &report)
	return report, err
}

func (s *Score) CalculateEfficacy() {
	s.Sensitivity = 0.0
	if s.Tp > 0 {
		s.Sensitivity = RoundedFloat64(float64(s.Tp) / float64(s.Tp+s.Fn))
	}
	s.Specificity = 0.0
	if s.Tn > 0 {
		s.Specificity = RoundedFloat64(float64(s.Tn) / float64(s.Tn+s.Fp))
	}
	s.Efficacy = (s.Sensitivity + s.Specificity) / 2
}

type RoundedFloat64 float64

func (r RoundedFloat64) MarshalJSON() ([]byte, error) {
        return []byte(r.String()), nil
}

func (r RoundedFloat64) String() string {
	// Like a float64, but printed with only three significant digits
        return strconv.FormatFloat(float64(r), 'g', 3, 64)
}
