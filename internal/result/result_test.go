package result

import "testing"

func claimFor(t *testing.T, r Report, f Feature) Claim {
	t.Helper()
	for _, c := range r.Claims {
		if c.Feature == f {
			return c
		}
	}
	t.Fatalf("no claim for %s", f)
	return Claim{}
}

func TestClaims(t *testing.T) {
	var r Report
	add := func(f Feature, l Level, s Status) {
		r.Add(Result{Name: string(f) + string(l) + string(s), Feature: f, Level: l, Status: s})
	}
	// x509-server: all MUST pass, a SHOULD fails -> conformant.
	add(FeatureX509Server, LevelMust, StatusPass)
	add(FeatureX509Server, LevelShould, StatusFail)
	// x509-client: everything skipped -> unsupported.
	add(FeatureX509Client, LevelMust, StatusSkip)
	// jwt-validate: one MUST fails -> non-conformant.
	add(FeatureJWTValidate, LevelMust, StatusPass)
	add(FeatureJWTValidate, LevelMust, StatusFail)
	// jwt-fetch: one MUST pass, one MUST error -> incomplete.
	add(FeatureJWTFetch, LevelMust, StatusPass)
	add(FeatureJWTFetch, LevelMust, StatusError)

	want := map[Feature]ClaimStatus{
		FeatureX509Server:  ClaimConformant,
		FeatureX509Client:  ClaimUnsupported,
		FeatureJWTValidate: ClaimNonConformant,
		FeatureJWTFetch:    ClaimIncomplete,
	}
	for f, s := range want {
		if got := claimFor(t, r, f).Status; got != s {
			t.Errorf("%s: claim %s, want %s", f, got, s)
		}
	}
	if r.Levels[LevelShould].Failed != 1 || r.Levels[LevelMust].Passed != 3 {
		t.Errorf("level counts wrong: %+v", r.Levels)
	}
	if r.Claims[0].Feature != FeatureX509Server {
		t.Errorf("claims not in feature order: %+v", r.Claims)
	}
}

func TestClaimNotRun(t *testing.T) {
	var r Report
	r.Add(Result{Name: "a", Feature: FeatureX509Server, Level: LevelOpt, Status: StatusFail})
	if got := claimFor(t, r, FeatureX509Server).Status; got != ClaimNotRun {
		t.Fatalf("claim %s, want not-run (only OPT tests)", got)
	}
}
