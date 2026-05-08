package result

import "encoding/json"

// Status represents the outcome of a single test case.
type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusSkip Status = "SKIP"
	StatusError Status = "ERROR"
)

// Result holds the outcome of one test case run.
type Result struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      Status `json:"status"`
	// Message contains a failure reason or skip reason when Status != PASS.
	Message string `json:"message,omitempty"`
}

// Report aggregates results across the full run.
type Report struct {
	Results []Result `json:"results"`
	Passed  int      `json:"passed"`
	Failed  int      `json:"failed"`
	Skipped int      `json:"skipped"`
	Errors  int      `json:"errors"`
}

// Add appends a result and updates the counters.
func (r *Report) Add(res Result) {
	r.Results = append(r.Results, res)
	switch res.Status {
	case StatusPass:
		r.Passed++
	case StatusFail:
		r.Failed++
	case StatusSkip:
		r.Skipped++
	case StatusError:
		r.Errors++
	}
}

// JSON returns the report as indented JSON bytes.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
