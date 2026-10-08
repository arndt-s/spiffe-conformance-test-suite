package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	"github.com/arndt-s/spiffe-conformance-test-suite/suite"
)

func init() {
	register("JV-1", "JS §4, WA §6.3",
		"Accepts a valid token and returns `sub` as the SPIFFE ID (positive control)", runJV1)

	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"} {
		register("JV-2/"+alg, "JS §2.1", "Accepts every supported `alg`", jv2(alg))
	}

	register("JV-3", "JS §2.1", "Rejects `alg: none`", runJV3)

	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		register("JV-4/"+alg, "JS §2.1", "Rejects HS256/HS384/HS512", jv4(alg, false))
	}
	register("JV-4/hmac-public-key", "JS §2.1", "Rejects HS256/HS384/HS512", jv4("HS256", true))

	register("JV-5", "JS §2.1",
		"Rejects asymmetric algorithms outside the list, even if the key is in the bundle", runJV5)

	register("JV-6/rs256-header-ec-key", "JS §4", "Rejects an `alg` that does not match the key type", runJV6RS256)
	register("JV-6/es384-header-p256-key", "JS §4", "Rejects an `alg` that does not match the key type", runJV6ES384)

	register("JV-7", "JS §3.2", "Rejects a token without `aud`",
		claimsNegative("a token without aud", func(c map[string]any) { delete(c, "aud") }))
	register("JV-8", "JS §3.2", "Rejects a token whose `aud` does not contain the validator's audience",
		claimsNegative("a token whose aud is [\"other\"]", func(c map[string]any) { c["aud"] = []string{"other"} }))
	register("JV-9", "JS §3.2", "Accepts an `aud` array that contains the validator's audience among others",
		claimsPositive(func(c map[string]any) { c["aud"] = []string{"other", suite.Audience} }))
	register("JV-10", "JS §4 (RFC 7519 §4.1.3)", "Accepts `aud` as a single string",
		claimsPositive(func(c map[string]any) { c["aud"] = suite.Audience }))
	register("JV-11", "JS §3.3", "Rejects a token without `exp`",
		claimsNegative("a token without exp", func(c map[string]any) { delete(c, "exp") }))
	register("JV-12", "JS §3.3, App. A", "Rejects an expired token",
		claimsNegative("a token that expired 5 minutes ago", func(c map[string]any) {
			now := time.Now()
			c["iat"] = now.Add(-10 * time.Minute).Unix()
			c["exp"] = now.Add(-5 * time.Minute).Unix()
		}))
	register("JV-13", "JS §4 (RFC 7519 §4.1.5)", "Rejects a token whose `nbf` is in the future",
		claimsNegative("a token whose nbf is 5 minutes in the future", func(c map[string]any) {
			c["nbf"] = time.Now().Add(5 * time.Minute).Unix()
		}))

	register("JV-14", "JS §4", "Rejects a token with a tampered signature", runJV14)
	register("JV-15", "JS §4", "Rejects a token with a tampered payload", runJV15)
	register("JV-16", "JS §4, WA §6.3", "Rejects a token signed by a key that is not in the bundle", runJV16)
	register("JV-17", "WA §6.3",
		"Rejects a token whose `sub` is in trust domain B but which is signed by trust domain A's key", runJV17)
	register("JV-18", "WA §6.3", "Rejects a token whose `sub` trust domain has no bundle", runJV18)
	register("JV-19", "JS §3.1", "Rejects a token whose `sub` is not a SPIFFE ID",
		claimsNegative("a token whose sub is https://test.example.org/jv-19", func(c map[string]any) {
			c["sub"] = "https://test.example.org/jv-19"
		}))

	register("JV-20/typ-JWT", "JS §2.3", "Accepts `typ` of `JWT`, `JOSE`, or no `typ`", headerPositive(map[string]any{"typ": "JWT"}))
	register("JV-20/typ-JOSE", "JS §2.3", "Accepts `typ` of `JWT`, `JOSE`, or no `typ`", headerPositive(map[string]any{"typ": "JOSE"}))
	register("JV-20/no-typ", "JS §2.3", "Accepts `typ` of `JWT`, `JOSE`, or no `typ`", headerPositive(map[string]any{"typ": nil}))
	register("JV-21", "JS §2.3", "Rejects any other `typ` value",
		headerNegative("a token with typ \"at+jwt\"", map[string]any{"typ": "at+jwt"}))
	register("JV-22", "JS §2.2", "Accepts a token without `kid`", headerPositive(map[string]any{"kid": nil}))
	register("JV-23", "JS §4 (RFC 7515 §4.1.11)", "Rejects a token with an unknown `crit` header",
		headerNegative("a token with an unknown crit header parameter", map[string]any{
			"crit":                           []string{"urn:spiffe-conformance:unknown"},
			"urn:spiffe-conformance:unknown": true,
		}))
	register("JV-24", "JS §1, §5.1", "Rejects JWS JSON serialization", runJV24)

	register("JV-25/two-parts", "JS §5.1", "Rejects a malformed compact token", runJV25TwoParts)
	register("JV-25/bad-base64", "JS §5.1", "Rejects a malformed compact token", runJV25BadBase64)
	register("JV-25/bad-json", "JS §5.1", "Rejects a malformed compact token", runJV25BadJSON)
}

func runJV1(ctx context.Context, env *suite.TestEnv) error {
	id := subID("JV-1")
	tok, err := validToken(env, id)
	if err != nil {
		return err
	}
	return expectAccepted(ctx, env, tok, id, "valid ES256 token")
}

// jv2 adds a key for alg to the bundle and expects a token signed with it to
// be accepted.
func jv2(alg string) suite.TestFunc {
	return func(ctx context.Context, env *suite.TestEnv) error {
		key, err := addKey(env, alg)
		if err != nil {
			return err
		}
		if err := serveBundles(ctx, env, "JV-2/"+alg, env.CA()); err != nil {
			return err
		}
		id := subID("JV-2/" + alg)
		tok, err := signToken(key, nil, ca.ValidJWTClaims(id, suite.Audience))
		if err != nil {
			return err
		}
		return expectAccepted(ctx, env, tok, id, alg+" token signed by a bundle key")
	}
}

func runJV3(ctx context.Context, env *suite.TestEnv) error {
	h, err := b64JSON(map[string]any{"alg": "none", "kid": defaultKey(env).ID, "typ": "JWT"})
	if err != nil {
		return err
	}
	p, err := b64JSON(ca.ValidJWTClaims(subID("JV-3"), suite.Audience))
	if err != nil {
		return err
	}
	return negative(ctx, env, "JV-3", h+"."+p+".", "an unsigned token with alg \"none\"")
}

// jv4 builds an HMAC-signed token whose kid names the bundle's ES256 key. With
// publicKey, the HMAC secret is that key's public key as a PEM "PUBLIC KEY"
// block (PKIX SubjectPublicKeyInfo), the classic algorithm-confusion secret;
// otherwise it is a random 32-byte secret.
func jv4(alg string, publicKey bool) suite.TestFunc {
	return func(ctx context.Context, env *suite.TestEnv) error {
		key := defaultKey(env)
		var secret []byte
		if publicKey {
			der, err := x509.MarshalPKIXPublicKey(key.Signer.Public())
			if err != nil {
				return suite.ExecErrorf("marshal public key: %w", err)
			}
			secret = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		} else {
			secret = make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				return suite.ExecErrorf("random secret: %w", err)
			}
		}
		var hf func() hash.Hash
		switch alg {
		case "HS256":
			hf = sha256.New
		case "HS384":
			hf = sha512.New384
		case "HS512":
			hf = sha512.New
		}
		h, err := b64JSON(map[string]any{"alg": alg, "kid": key.ID, "typ": "JWT"})
		if err != nil {
			return err
		}
		p, err := b64JSON(ca.ValidJWTClaims(subID("JV-4/"+alg), suite.Audience))
		if err != nil {
			return err
		}
		mac := hmac.New(hf, secret)
		mac.Write([]byte(h + "." + p))
		tok := h + "." + p + "." + b64(mac.Sum(nil))
		what := "an " + alg + " token keyed with a random secret"
		if publicKey {
			what = "an HS256 token keyed with the bundle key's PEM public key"
		}
		return negative(ctx, env, "JV-4/"+alg, tok, what)
	}
}

// runJV5 publishes an Ed25519 key (with an extra ES256 key as an update
// barrier) and expects an EdDSA token signed by it to be rejected.
func runJV5(ctx context.Context, env *suite.TestEnv) error {
	ed, err := addKey(env, "EdDSA")
	if err != nil {
		return err
	}
	barrier, err := addKey(env, "ES256")
	if err != nil {
		return err
	}
	if err := serveBundles(ctx, env, "JV-5", env.CA()); err != nil {
		return err
	}
	// Accepting a token signed by the new ES256 key shows the bundle with the
	// Ed25519 key has been applied.
	// An SDK that drops the whole bundle because of the Ed25519 key fails
	// here: it rejects a valid token signed by a key in the served bundle.
	if err := positiveControl(ctx, env, barrier, suite.TrustDomain+"/control/jv-5-barrier"); err != nil {
		if isPlain(err) {
			return fmt.Errorf("the bundle containing the Ed25519 key was not applied (a token signed by an ES256 key in the same bundle): %w", err)
		}
		return err
	}
	tok, err := signToken(ed, nil, ca.ValidJWTClaims(subID("JV-5"), suite.Audience))
	if err != nil {
		return err
	}
	return expectRejected(env, tok, "an EdDSA token signed by an Ed25519 key in the bundle")
}

// runJV6RS256 sends an ES256 signature by the bundle's EC key under an RS256
// header: an SDK that picks the algorithm from the key type accepts it.
func runJV6RS256(ctx context.Context, env *suite.TestEnv) error {
	tok, err := signToken(defaultKey(env), map[string]any{"alg": "RS256"},
		ca.ValidJWTClaims(subID("JV-6/rs256-header-ec-key"), suite.Audience))
	if err != nil {
		return err
	}
	return negative(ctx, env, "JV-6/rs256-header-ec-key", tok,
		"an RS256-labelled token whose kid names a P-256 key (ES256 signature)")
}

// runJV6ES384 sends an ES384 header whose kid names a P-256 key, signed with
// that key over a SHA-384 digest (64-byte R||S): an SDK that trusts the header
// and does not check the curve accepts it.
func runJV6ES384(ctx context.Context, env *suite.TestEnv) error {
	key := defaultKey(env)
	priv, ok := key.Signer.(*ecdsa.PrivateKey)
	if !ok {
		return suite.ExecErrorf("default JWT key is not ECDSA")
	}
	h, err := b64JSON(map[string]any{"alg": "ES384", "kid": key.ID, "typ": "JWT"})
	if err != nil {
		return err
	}
	p, err := b64JSON(ca.ValidJWTClaims(subID("JV-6/es384-header-p256-key"), suite.Audience))
	if err != nil {
		return err
	}
	input := h + "." + p
	digest := sha512.Sum384([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return suite.ExecErrorf("sign: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return negative(ctx, env, "JV-6/es384-header-p256-key", input+"."+b64(sig),
		"an ES384-labelled token signed with a P-256 key")
}

// claimsNegative signs a token whose catalogue-default claims are changed by
// mutate, and expects it to be rejected.
func claimsNegative(what string, mutate func(map[string]any)) suite.TestFunc {
	return func(ctx context.Context, env *suite.TestEnv) error {
		claims := ca.ValidJWTClaims(suite.TrustDomain+"/claims-negative", suite.Audience)
		mutate(claims)
		tok, err := signToken(defaultKey(env), nil, claims)
		if err != nil {
			return err
		}
		return negative(ctx, env, "claims", tok, what)
	}
}

// claimsPositive signs a token whose default claims are changed by mutate and
// expects it to be accepted.
func claimsPositive(mutate func(map[string]any)) suite.TestFunc {
	return func(ctx context.Context, env *suite.TestEnv) error {
		id := suite.TrustDomain + "/claims-positive"
		claims := ca.ValidJWTClaims(id, suite.Audience)
		mutate(claims)
		tok, err := signToken(defaultKey(env), nil, claims)
		if err != nil {
			return err
		}
		return expectAccepted(ctx, env, tok, id, "valid token")
	}
}

// headerPositive signs a default token with header overrides (nil deletes)
// and expects it to be accepted.
func headerPositive(header map[string]any) suite.TestFunc {
	return func(ctx context.Context, env *suite.TestEnv) error {
		id := suite.TrustDomain + "/header-positive"
		tok, err := signToken(defaultKey(env), header, ca.ValidJWTClaims(id, suite.Audience))
		if err != nil {
			return err
		}
		return expectAccepted(ctx, env, tok, id, fmt.Sprintf("valid token with header overrides %v", header))
	}
}

// headerNegative signs a default token with header overrides and expects it
// to be rejected.
func headerNegative(what string, header map[string]any) suite.TestFunc {
	return func(ctx context.Context, env *suite.TestEnv) error {
		tok, err := signToken(defaultKey(env), header,
			ca.ValidJWTClaims(suite.TrustDomain+"/header-negative", suite.Audience))
		if err != nil {
			return err
		}
		return negative(ctx, env, "header", tok, what)
	}
}

func runJV14(ctx context.Context, env *suite.TestEnv) error {
	tok, err := validToken(env, subID("JV-14"))
	if err != nil {
		return err
	}
	parts := strings.Split(tok, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return suite.ExecErrorf("decode signature: %w", err)
	}
	sig[len(sig)/2] ^= 0x01
	parts[2] = b64(sig)
	return negative(ctx, env, "JV-14", strings.Join(parts, "."), "a token with one signature bit flipped")
}

func runJV15(ctx context.Context, env *suite.TestEnv) error {
	tok, err := validToken(env, subID("JV-15"))
	if err != nil {
		return err
	}
	parts := strings.Split(tok, ".")
	// Same claims except sub, re-encoded; the original signature is kept.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return suite.ExecErrorf("decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return suite.ExecErrorf("parse payload: %w", err)
	}
	claims["sub"] = suite.TrustDomain + "/admin"
	if parts[1], err = b64JSON(claims); err != nil {
		return err
	}
	return negative(ctx, env, "JV-15", strings.Join(parts, "."), "a token whose sub was changed after signing")
}

// runJV16 signs with a key that is not in any bundle (unknown kid).
func runJV16(ctx context.Context, env *suite.TestEnv) error {
	other, err := newCA(suite.TrustDomain)
	if err != nil {
		return err
	}
	tok, err := signToken(other.JWTKeys()[0], nil, ca.ValidJWTClaims(subID("JV-16"), suite.Audience))
	if err != nil {
		return err
	}
	return negative(ctx, env, "JV-16", tok, "a token signed by a key that is not in the bundle")
}

const otherTD = "spiffe://other.example.org"

// runJV17 serves bundles for A (suite) and B; the token's sub is in B but it
// is signed by A's key, whose kid exists only in A's bundle.
func runJV17(ctx context.Context, env *suite.TestEnv) error {
	b, err := newCA(otherTD)
	if err != nil {
		return err
	}
	if err := serveBundles(ctx, env, "JV-17", env.CA(), b); err != nil {
		return err
	}
	// Accepting B's own token shows B's bundle is in place.
	if err := positiveControl(ctx, env, b.JWTKeys()[0], otherTD+"/control/jv-17"); err != nil {
		return err
	}
	tok, err := signToken(defaultKey(env), nil, ca.ValidJWTClaims(otherTD+"/jv-17", suite.Audience))
	if err != nil {
		return err
	}
	return expectRejected(env, tok, "a token for "+otherTD+" signed by "+suite.TrustDomain+"'s key")
}

// runJV18: the sub's trust domain has no bundle; the token is signed by the
// suite trust domain's key.
func runJV18(ctx context.Context, env *suite.TestEnv) error {
	tok, err := validToken(env, "spiffe://unknown.example.org/jv-18")
	if err != nil {
		return err
	}
	return negative(ctx, env, "JV-18", tok,
		"a token for spiffe://unknown.example.org (no bundle) signed by "+suite.TrustDomain+"'s key")
}

// runJV24 re-encodes a valid token in flattened JWS JSON serialization.
func runJV24(ctx context.Context, env *suite.TestEnv) error {
	tok, err := validToken(env, subID("JV-24"))
	if err != nil {
		return err
	}
	parts := strings.Split(tok, ".")
	js, err := json.Marshal(map[string]string{"protected": parts[0], "payload": parts[1], "signature": parts[2]})
	if err != nil {
		return suite.ExecErrorf("marshal: %w", err)
	}
	return negative(ctx, env, "JV-24", string(js), "a validly signed token in JWS JSON serialization")
}

func runJV25TwoParts(ctx context.Context, env *suite.TestEnv) error {
	tok, err := validToken(env, subID("JV-25/two-parts"))
	if err != nil {
		return err
	}
	return negative(ctx, env, "JV-25/two-parts", tok[:strings.LastIndex(tok, ".")],
		"a token with two parts (signature removed)")
}

// runJV25BadBase64 puts a character outside the base64url alphabet in the
// middle of the payload part. The signature is computed over the token's
// actual signing input, so only the encoding is wrong.
func runJV25BadBase64(ctx context.Context, env *suite.TestEnv) error {
	key := defaultKey(env)
	h, err := b64JSON(map[string]any{"alg": key.Alg, "kid": key.ID, "typ": "JWT"})
	if err != nil {
		return err
	}
	p, err := b64JSON(ca.ValidJWTClaims(subID("JV-25/bad-base64"), suite.Audience))
	if err != nil {
		return err
	}
	mid := len(p) / 2
	p = p[:mid] + "!" + p[mid:]
	tok, err := signInput(key, h+"."+p)
	if err != nil {
		return err
	}
	return negative(ctx, env, "JV-25/bad-base64", tok,
		"a validly signed token whose payload contains a non-base64url character")
}

// runJV25BadJSON signs a payload that base64url-decodes to invalid JSON.
func runJV25BadJSON(ctx context.Context, env *suite.TestEnv) error {
	key := defaultKey(env)
	h, err := b64JSON(map[string]any{"alg": key.Alg, "kid": key.ID, "typ": "JWT"})
	if err != nil {
		return err
	}
	p := b64([]byte(`{"sub":"` + subID("JV-25/bad-json") + `","aud":["conformance"],`))
	tok, err := signInput(key, h+"."+p)
	if err != nil {
		return err
	}
	return negative(ctx, env, "JV-25/bad-json", tok, "a validly signed token whose payload is not valid JSON")
}
