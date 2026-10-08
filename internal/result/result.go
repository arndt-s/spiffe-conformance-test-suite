// Package result defines test results, reports and conformance claims.
package result

import (
	"encoding/json"
	"sort"
)

// Status represents the outcome of a single test case.
type Status string

const (
	StatusPass  Status = "PASS"
	StatusFail  Status = "FAIL"
	StatusSkip  Status = "SKIP"
	StatusError Status = "ERROR"
)

// Level is the requirement level of a test case (catalogue §1.1).
type Level string

const (
	LevelMust   Level = "MUST"
	LevelShould Level = "SHOULD"
	LevelOpt    Level = "OPT"
)

// Feature groups test cases by the harness capability they need
// (harness contract §5). Conformance is claimed per feature.
type Feature string

const (
	FeatureX509Server  Feature = "x509-server"
	FeatureX509Client  Feature = "x509-client"
	FeatureJWTValidate Feature = "jwt-validate"
	FeatureJWTFetch    Feature = "jwt-fetch"
)

// Features lists all features in report order.
var Features = []Feature{FeatureX509Server, FeatureX509Client, FeatureJWTValidate, FeatureJWTFetch}

// Result holds the outcome of one test case run.
type Result struct {
	// Name is the catalogue test ID, e.g. "XV-8/server".
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Level       Level   `json:"level"`
	Feature     Feature `json:"feature"`
	// Ref is the specification reference, e.g. "XS §5.2".
	Ref    string `json:"ref,omitempty"`
	Status Status `json:"status"`
	// Message contains a failure reason or skip reason when Status != PASS.
	Message string `json:"message,omitempty"`
	// Delegated is set when the SDK called the Workload API's ValidateJWTSVID
	// during the test: JWT validation results then reflect the mock server's
	// validator rather than the SDK's.
	Delegated bool `json:"delegated,omitempty"`
}

// ClaimStatus is the conformance verdict for one feature.
type ClaimStatus string

const (
	// ClaimConformant: every MUST test of the feature passed.
	ClaimConformant ClaimStatus = "conformant"
	// ClaimNonConformant: at least one MUST test of the feature failed.
	ClaimNonConformant ClaimStatus = "non-conformant"
	// ClaimIncomplete: no MUST test failed, but some were skipped or could not
	// be executed, so conformance cannot be claimed.
	ClaimIncomplete ClaimStatus = "incomplete"
	// ClaimUnsupported: the harness does not support the feature (every MUST
	// test was skipped).
	ClaimUnsupported ClaimStatus = "unsupported"
	// ClaimNotRun: no MUST test of the feature was selected.
	ClaimNotRun ClaimStatus = "not-run"
)

// Claim summarises the MUST tests of one feature.
type Claim struct {
	Feature Feature     `json:"feature"`
	Status  ClaimStatus `json:"status"`
	Passed  int         `json:"must_passed"`
	Failed  int         `json:"must_failed"`
	Skipped int         `json:"must_skipped"`
	Errors  int         `json:"must_errors"`
	// Delegated reports that at least one result of the feature was delegated
	// to the Workload API's ValidateJWTSVID.
	Delegated bool `json:"delegated,omitempty"`
}

// LevelCounts counts results by status for one level.
type LevelCounts struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Errors  int `json:"errors"`
}

// Report aggregates results across the full run.
type Report struct {
	Results []Result              `json:"results"`
	Passed  int                   `json:"passed"`
	Failed  int                   `json:"failed"`
	Skipped int                   `json:"skipped"`
	Errors  int                   `json:"errors"`
	Levels  map[Level]LevelCounts `json:"levels"`
	Claims  []Claim               `json:"claims"`
	// Partial is set when only a subset of the test cases was selected; the
	// claims then only cover that subset.
	Partial bool `json:"partial,omitempty"`
}

// Add appends a result and updates the counters.
func (r *Report) Add(res Result) {
	r.Results = append(r.Results, res)
	if r.Levels == nil {
		r.Levels = map[Level]LevelCounts{}
	}
	lc := r.Levels[res.Level]
	switch res.Status {
	case StatusPass:
		r.Passed++
		lc.Passed++
	case StatusFail:
		r.Failed++
		lc.Failed++
	case StatusSkip:
		r.Skipped++
		lc.Skipped++
	case StatusError:
		r.Errors++
		lc.Errors++
	}
	r.Levels[res.Level] = lc
	r.Claims = computeClaims(r.Results)
}

func computeClaims(results []Result) []Claim {
	byFeature := map[Feature]*Claim{}
	for _, f := range Features {
		byFeature[f] = &Claim{Feature: f}
	}
	for _, res := range results {
		c, ok := byFeature[res.Feature]
		if !ok {
			c = &Claim{Feature: res.Feature}
			byFeature[res.Feature] = c
		}
		if res.Delegated {
			c.Delegated = true
		}
		if res.Level != LevelMust {
			continue
		}
		switch res.Status {
		case StatusPass:
			c.Passed++
		case StatusFail:
			c.Failed++
		case StatusSkip:
			c.Skipped++
		case StatusError:
			c.Errors++
		}
	}

	claims := make([]Claim, 0, len(byFeature))
	for _, c := range byFeature {
		total := c.Passed + c.Failed + c.Skipped + c.Errors
		switch {
		case total == 0:
			c.Status = ClaimNotRun
		case c.Failed > 0:
			c.Status = ClaimNonConformant
		case c.Skipped == total:
			c.Status = ClaimUnsupported
		case c.Skipped > 0 || c.Errors > 0:
			c.Status = ClaimIncomplete
		default:
			c.Status = ClaimConformant
		}
		claims = append(claims, *c)
	}
	order := map[Feature]int{}
	for i, f := range Features {
		order[f] = i
	}
	sort.Slice(claims, func(i, j int) bool {
		oi, iok := order[claims[i].Feature]
		oj, jok := order[claims[j].Feature]
		if iok && jok {
			return oi < oj
		}
		if iok != jok {
			return iok
		}
		return claims[i].Feature < claims[j].Feature
	})
	return claims
}

// JSON returns the report as indented JSON bytes.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
