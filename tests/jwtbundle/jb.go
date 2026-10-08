package jwtbundle

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	suite.Register(suite.TestCase{
		ID:          "JB-1",
		Description: "Picks up a key added by a streamed bundle update",
		Level:       suite.MUST,
		Feature:     suite.JWTValidate,
		Ref:         "WA §4.3",
		Run:         runJB1,
	})
	suite.Register(suite.TestCase{
		ID:          "JB-2",
		Description: "Stops accepting a key removed by a streamed bundle update",
		Level:       suite.MUST,
		Feature:     suite.JWTValidate,
		Ref:         "WA §4.4",
		Run:         runJB2,
	})
	suite.Register(suite.TestCase{
		ID:          "JB-3",
		Description: "Stops accepting tokens from a trust domain whose bundle was removed",
		Level:       suite.SHOULD,
		Feature:     suite.JWTValidate,
		Ref:         "WA §4.4",
		Run:         runJB3,
	})
	suite.Register(suite.TestCase{
		ID:          "JB-4",
		Description: "Selects the verification key by kid among several keys",
		Level:       suite.MUST,
		Feature:     suite.JWTValidate,
		Ref:         "JS §6.2 (RFC 7515 §4.1.4)",
		Run:         runJB4,
	})
	// A key with use "x509-svid" must be ignored (JS §6.2). Whether a key
	// without "use" in a Workload API JWT bundle must be ignored is not clear:
	// TB §4.2.2 requires it for SPIFFE bundles, but WA §6.2.2 only calls the
	// Workload API's JWT bundle a standard JWK Set. That variant is OPT.
	for _, v := range []struct {
		name, use, desc string
		level           suite.Level
		ref             string
	}{
		{"missing-use", "", "missing", suite.OPT, "TB §4.2.2 (WA §6.2.2 unclear)"},
		{"x509-svid-use", "x509-svid", `"x509-svid"`, suite.MUST, "JS §6.2, TB §4.2.2"},
	} {
		v := v
		suite.Register(suite.TestCase{
			ID:          "JB-5/" + v.name,
			Description: "Ignores JWKs whose use is missing or is not jwt-svid (use " + v.desc + ")",
			Level:       v.level,
			Feature:     suite.JWTValidate,
			Ref:         v.ref,
			Run: func(ctx context.Context, env *suite.TestEnv) error {
				return runJB5(ctx, env, v.use)
			},
		})
	}
	suite.Register(suite.TestCase{
		ID:          "JB-6",
		Description: "Ignores JWKs with an unknown kty without discarding the rest of the bundle",
		Level:       suite.MUST,
		Feature:     suite.JWTValidate,
		Ref:         "TB §4.2.1, §4.1.3",
		Run:         runJB6,
	})
	suite.Register(suite.TestCase{
		ID:          "JB-7",
		Description: `Treats a bundle with empty keys as "trust nothing" for that trust domain`,
		Level:       suite.MUST,
		Feature:     suite.JWTValidate,
		Ref:         "TB §4.1.3",
		Run:         runJB7,
	})
	suite.Register(suite.TestCase{
		ID:          "JB-8",
		Description: "Accepts a token from a federated trust domain using that trust domain's bundle",
		Level:       suite.MUST,
		Feature:     suite.JWTValidate,
		Ref:         "WA §6.2.2, §6.3",
		Run:         runJB8,
	})
}

// initialControl checks that the SDK accepts a token signed by the key in the
// bundle served at startup, and returns that key.
func initialControl(ctx context.Context, env *suite.TestEnv, sub string) (*ca.JWTKey, error) {
	k0 := env.CA().JWTKeys()[0]
	tok, err := token(env.CA(), sub, k0)
	if err != nil {
		return nil, err
	}
	if err := waitAccepted(ctx, env, tok, "positive control: token signed by the initial bundle key was not accepted"); err != nil {
		return nil, err
	}
	return k0, nil
}

func runJB1(ctx context.Context, env *suite.TestEnv) error {
	const sub = suite.TrustDomain + "/jb-1"
	k0, err := initialControl(ctx, env, sub)
	if err != nil {
		return err
	}
	k1, err := newKey(env)
	if err != nil {
		return err
	}
	b, err := jwks([]*ca.JWTKey{k0, k1})
	if err != nil {
		return err
	}
	if err := pushBundles(env, bundleSet{suite.TrustDomain: b}); err != nil {
		return err
	}
	tok, err := token(env.CA(), sub, k1)
	if err != nil {
		return err
	}
	return waitAccepted(ctx, env, tok, "token signed by the key added in a bundle update was not accepted")
}

func runJB2(ctx context.Context, env *suite.TestEnv) error {
	const sub = suite.TrustDomain + "/jb-2"
	k0 := env.CA().JWTKeys()[0]
	k1, err := newKey(env)
	if err != nil {
		return err
	}
	k2, err := newKey(env)
	if err != nil {
		return err
	}

	// Positive control: k1 is trusted.
	b, err := jwks([]*ca.JWTKey{k0, k1})
	if err != nil {
		return err
	}
	if err := pushBundles(env, bundleSet{suite.TrustDomain: b}); err != nil {
		return err
	}
	tok1, err := token(env.CA(), sub, k1)
	if err != nil {
		return err
	}
	if err := waitAccepted(ctx, env, tok1, "positive control: token signed by the added key was not accepted"); err != nil {
		return err
	}

	// Remove k1; k2 in the same update is the barrier.
	b, err = jwks([]*ca.JWTKey{k0, k2})
	if err != nil {
		return err
	}
	if err := pushBundles(env, bundleSet{suite.TrustDomain: b}); err != nil {
		return err
	}
	tok2, err := token(env.CA(), sub, k2)
	if err != nil {
		return err
	}
	if err := waitAccepted(ctx, env, tok2, "barrier: token signed by the key added together with the removal was not accepted"); err != nil {
		return err
	}
	return expectRejected(env, tok1, "a token signed by a key removed from the bundle")
}

func runJB3(ctx context.Context, env *suite.TestEnv) error {
	const sub = suite.TrustDomain + "/jb-3"
	foreignSub := ForeignTrustDomain + "/jb-3"
	foreign, err := newForeignCA()
	if err != nil {
		return err
	}
	k0 := env.CA().JWTKeys()[0]
	kf := foreign.JWTKeys()[0]
	kBarrier, err := newKey(env)
	if err != nil {
		return err
	}

	own, err := jwks([]*ca.JWTKey{k0})
	if err != nil {
		return err
	}
	fb, err := jwks([]*ca.JWTKey{kf})
	if err != nil {
		return err
	}
	if err := pushBundles(env, bundleSet{suite.TrustDomain: own, ForeignTrustDomain: fb}); err != nil {
		return err
	}
	ftok, err := token(foreign, foreignSub, kf)
	if err != nil {
		return err
	}
	if err := waitAccepted(ctx, env, ftok, "positive control: token from the federated trust domain was not accepted"); err != nil {
		return err
	}

	// Drop the foreign bundle; a new own key is the barrier.
	own, err = jwks([]*ca.JWTKey{k0, kBarrier})
	if err != nil {
		return err
	}
	if err := pushBundles(env, bundleSet{suite.TrustDomain: own}); err != nil {
		return err
	}
	btok, err := token(env.CA(), sub, kBarrier)
	if err != nil {
		return err
	}
	if err := waitAccepted(ctx, env, btok, "barrier: token signed by the key added together with the bundle removal was not accepted"); err != nil {
		return err
	}
	return expectRejected(env, ftok, "a token from a trust domain whose bundle was removed")
}

func runJB4(ctx context.Context, env *suite.TestEnv) error {
	const sub = suite.TrustDomain + "/jb-4"
	var keys []*ca.JWTKey
	for i := 0; i < 3; i++ {
		k, err := newKey(env)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	b, err := jwks(keys)
	if err != nil {
		return err
	}
	if err := pushBundles(env, bundleSet{suite.TrustDomain: b}); err != nil {
		return err
	}
	// Barrier: the third key shows the update was applied.
	tok3, err := token(env.CA(), sub, keys[2])
	if err != nil {
		return err
	}
	if err := waitAccepted(ctx, env, tok3, "barrier: token signed by the third bundle key was not accepted"); err != nil {
		return err
	}
	tok2, err := token(env.CA(), sub, keys[1])
	if err != nil {
		return err
	}
	v, err := env.ValidateJWT(tok2, suite.Audience)
	if err != nil {
		return err
	}
	if !v.Accepted {
		return fmt.Errorf("SDK rejected a token signed by the second of three bundle keys (kid %s): %s", keys[1].ID, v.Message)
	}
	return nil
}

func runJB5(ctx context.Context, env *suite.TestEnv, use string) error {
	const sub = suite.TrustDomain + "/jb-5"
	k0, err := initialControl(ctx, env, sub)
	if err != nil {
		return err
	}
	bad, err := newKey(env)
	if err != nil {
		return err
	}
	bad.Use = use
	kBarrier, err := newKey(env)
	if err != nil {
		return err
	}
	b, err := jwks([]*ca.JWTKey{k0, bad, kBarrier})
	if err != nil {
		return err
	}
	if err := pushBundles(env, bundleSet{suite.TrustDomain: b}); err != nil {
		return err
	}
	btok, err := token(env.CA(), sub, kBarrier)
	if err != nil {
		return err
	}
	if err := waitAccepted(ctx, env, btok, "other keys must keep working: token signed by a jwt-svid key in the same bundle was not accepted"); err != nil {
		return err
	}
	badTok, err := token(env.CA(), sub, bad)
	if err != nil {
		return err
	}
	what := "a token signed by a JWK without use"
	if use != "" {
		what = fmt.Sprintf("a token signed by a JWK with use %q", use)
	}
	return expectRejected(env, badTok, what)
}

func runJB6(ctx context.Context, env *suite.TestEnv) error {
	const sub = suite.TrustDomain + "/jb-6"
	k0, err := initialControl(ctx, env, sub)
	if err != nil {
		return err
	}
	kNew, err := newKey(env)
	if err != nil {
		return err
	}
	unknown := json.RawMessage(`{"kty":"SCTS-UNKNOWN","use":"jwt-svid","kid":"jb-6-unknown-kty","k":"AQAB"}`)
	// Place the unknown entry before the new key so a parser that stops at
	// the first bad entry loses the new key.
	set := struct {
		Keys []json.RawMessage `json:"keys"`
	}{}
	head, err := jwks([]*ca.JWTKey{k0})
	if err != nil {
		return err
	}
	tail, err := jwks([]*ca.JWTKey{kNew})
	if err != nil {
		return err
	}
	var h, t struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(head, &h); err != nil {
		return suite.ExecErrorf("decode JWKS: %w", err)
	}
	if err := json.Unmarshal(tail, &t); err != nil {
		return suite.ExecErrorf("decode JWKS: %w", err)
	}
	set.Keys = append(append(append(set.Keys, h.Keys...), unknown), t.Keys...)
	b, err := json.Marshal(set)
	if err != nil {
		return suite.ExecErrorf("encode JWKS: %w", err)
	}
	if err := pushBundles(env, bundleSet{suite.TrustDomain: b}); err != nil {
		return err
	}
	tok, err := token(env.CA(), sub, kNew)
	if err != nil {
		return err
	}
	if err := waitAccepted(ctx, env, tok, "bundle with an unknown-kty JWK: token signed by a valid key listed after it was not accepted"); err != nil {
		return err
	}
	tok0, err := token(env.CA(), sub, k0)
	if err != nil {
		return err
	}
	v, err := env.ValidateJWT(tok0, suite.Audience)
	if err != nil {
		return err
	}
	if !v.Accepted {
		return fmt.Errorf("bundle with an unknown-kty JWK: token signed by a valid key listed before it was rejected: %s", v.Message)
	}
	return nil
}

func runJB7(ctx context.Context, env *suite.TestEnv) error {
	const sub = suite.TrustDomain + "/jb-7"
	foreignSub := ForeignTrustDomain + "/jb-7"
	k0 := env.CA().JWTKeys()[0]
	tok0, err := token(env.CA(), sub, k0)
	if err != nil {
		return err
	}
	if err := waitAccepted(ctx, env, tok0, "positive control: token signed by the initial bundle key was not accepted"); err != nil {
		return err
	}

	// Own bundle becomes empty; a foreign trust domain's bundle in the same
	// update is the barrier.
	foreign, err := newForeignCA()
	if err != nil {
		return err
	}
	empty, err := jwks(nil)
	if err != nil {
		return err
	}
	fb, err := jwks(foreign.JWTKeys())
	if err != nil {
		return err
	}
	if err := pushBundles(env, bundleSet{suite.TrustDomain: empty, ForeignTrustDomain: fb}); err != nil {
		return err
	}
	ftok, err := token(foreign, foreignSub, foreign.JWTKeys()[0])
	if err != nil {
		return err
	}
	if err := waitAccepted(ctx, env, ftok, "barrier: token from the trust domain added in the same update was not accepted"); err != nil {
		return err
	}
	return expectRejected(env, tok0, `a token from a trust domain whose bundle has an empty "keys" array`)
}

func runJB8(ctx context.Context, env *suite.TestEnv) error {
	foreignSub := ForeignTrustDomain + "/jb-8"
	foreign, err := newForeignCA()
	if err != nil {
		return err
	}
	own, err := jwks(env.CA().JWTKeys())
	if err != nil {
		return err
	}
	fb, err := jwks(foreign.JWTKeys())
	if err != nil {
		return err
	}
	if err := pushBundles(env, bundleSet{suite.TrustDomain: own, ForeignTrustDomain: fb}); err != nil {
		return err
	}
	ftok, err := token(foreign, foreignSub, foreign.JWTKeys()[0])
	if err != nil {
		return err
	}
	if err := waitAccepted(ctx, env, ftok, "token from the federated trust domain was not accepted"); err != nil {
		return err
	}
	v, err := env.ValidateJWT(ftok, suite.Audience)
	if err != nil {
		return err
	}
	if !v.Accepted {
		return fmt.Errorf("token from the federated trust domain was accepted once, then rejected: %s", v.Message)
	}
	if v.SPIFFEID != "" && v.SPIFFEID != foreignSub {
		return fmt.Errorf("SDK reported SPIFFE ID %q, want %q", v.SPIFFEID, foreignSub)
	}
	return nil
}
