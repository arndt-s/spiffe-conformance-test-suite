package jwt

import (
	"context"
	"strings"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

// SPIFFE ID parsing, exercised through the `sub` of validly signed JWT-SVIDs
// (catalogue §7). Each token is signed by the suite trust domain's key.
//
// For invalid IDs whose trust domain is not test.example.org (empty or with an
// invalid character) no bundle can be served: a bundle keyed by an invalid
// trust domain would make strict SDKs drop the whole bundle update. For those
// two cases a rejection may come from the missing bundle rather than from ID
// parsing.

const tdHost = "test.example.org"

var invalidIDs = []struct{ name, id string }{
	{"empty-trust-domain", "spiffe:///a"},
	{"port", "spiffe://" + tdHost + ":8080/a"},
	{"userinfo", "spiffe://u@" + tdHost + "/a"},
	{"query", suite.TrustDomain + "/a?x=1"},
	{"fragment", suite.TrustDomain + "/a#f"},
	{"percent-encoded", suite.TrustDomain + "/%41"},
	{"empty-segment", suite.TrustDomain + "/a//b"},
	{"dot-segment", suite.TrustDomain + "/a/./b"},
	{"dot-dot-segment", suite.TrustDomain + "/a/../b"},
	{"trailing-slash", suite.TrustDomain + "/a/"},
	{"invalid-path-char", suite.TrustDomain + "/a!b"},
	{"invalid-trust-domain-char", "spiffe://t$d/a"},
}

func init() {
	for _, c := range invalidIDs {
		register("ID-1/"+c.name, "ID §2, §2.1, §2.2", "Rejects invalid SPIFFE IDs", id1(c.name, c.id))
	}
	register("ID-2/path-chars", "ID §2.1, §2.2, §2.3", "Accepts valid edge-case SPIFFE IDs",
		id2("", suite.TrustDomain+"/Path.With-Mixed_Case/a.b-c_D/..x/x.."))
	register("ID-2/trust-domain-chars", "ID §2.1, §2.2, §2.3", "Accepts valid edge-case SPIFFE IDs",
		id2("spiffe://td_1.example-2.org", "spiffe://td_1.example-2.org/id-2"))
	register("ID-2/ipv4-trust-domain", "ID §2.1, §2.2, §2.3", "Accepts valid edge-case SPIFFE IDs",
		id2("spiffe://192.168.1.1", "spiffe://192.168.1.1/id-2"))
	register("ID-2/max-length", "ID §2.1, §2.2, §2.3", "Accepts valid edge-case SPIFFE IDs",
		id2("", maxLengthID()))
}

func id1(name, sub string) suite.TestFunc {
	return func(ctx context.Context, env *suite.TestEnv) error {
		tok, err := validToken(env, sub)
		if err != nil {
			return err
		}
		return negative(ctx, env, "ID-1/"+name, tok, "a token whose sub is the invalid SPIFFE ID "+sub)
	}
}

// id2 expects a token for sub to be accepted with sub reported unchanged. If
// td is set, sub is in that trust domain: a bundle is served for it (alongside
// the suite's) and the token is signed with its key.
func id2(td, sub string) suite.TestFunc {
	return func(ctx context.Context, env *suite.TestEnv) error {
		key := defaultKey(env)
		if td != "" {
			other, err := newCA(td)
			if err != nil {
				return err
			}
			if err := serveBundles(ctx, env, "ID-2", env.CA(), other); err != nil {
				return err
			}
			key = other.JWTKeys()[0]
		}
		tok, err := signToken(key, nil, ca.ValidJWTClaims(sub, suite.Audience))
		if err != nil {
			return err
		}
		return expectAccepted(ctx, env, tok, sub, "token whose sub is a valid edge-case SPIFFE ID")
	}
}

// maxLengthID returns a 2048-byte SPIFFE ID in the suite trust domain, made of
// 100-character path segments (ID §2.3: implementations MUST support SPIFFE
// IDs up to 2048 bytes).
func maxLengthID() string {
	var b strings.Builder
	b.WriteString(suite.TrustDomain)
	seg := strings.Repeat("a", 100)
	for b.Len()+1+len(seg) <= 2048 {
		b.WriteString("/" + seg)
	}
	if rest := 2048 - b.Len() - 1; rest > 0 {
		b.WriteString("/" + strings.Repeat("b", rest))
	}
	return b.String()
}
