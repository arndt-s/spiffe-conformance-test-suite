package workloadapi

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/arndt-s/spiffe-conformance-test-suite/internal/ca"
	workloadv1 "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const td = "spiffe://test.example.org"

func startServer(t *testing.T) (*Server, workloadv1.SpiffeWorkloadAPIClient) {
	t.Helper()
	s := NewServer(filepath.Join(t.TempDir(), "api.sock"))
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)

	conn, err := grpc.NewClient("unix://"+s.SocketPath(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return s, workloadv1.NewSpiffeWorkloadAPIClient(conn)
}

func withHeader(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return metadata.AppendToOutgoingContext(ctx, "workload.spiffe.io", "true")
}

func newCA(t *testing.T, trustDomain string) *ca.CA {
	t.Helper()
	c, err := ca.New(trustDomain)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMissingHeaderIsRejectedAndRecorded(t *testing.T) {
	s, client := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.FetchJWTSVID(ctx, &workloadv1.JWTSVIDRequest{Audience: []string{"a"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("got %v, want InvalidArgument", err)
	}
	calls := s.Calls()
	if len(calls) != 1 || calls[0].HasHeader || calls[0].Code != codes.InvalidArgument {
		t.Fatalf("unexpected call record: %+v", calls)
	}
}

func TestFetchX509BundlesKeyedByTrustDomainID(t *testing.T) {
	s, client := startServer(t)
	local := newCA(t, td)
	fed := newCA(t, "spiffe://fed.example.org")
	svid, err := local.IssueX509SVID(td + "/workload")
	if err != nil {
		t.Fatal(err)
	}
	s.SetX509State(&X509State{
		Materials:        []*ca.X509SVIDMaterial{svid},
		FederatedBundles: map[string][][]byte{"spiffe://fed.example.org": {fed.CACertDER()}},
	})

	stream, err := client.FetchX509Bundles(withHeader(t), &workloadv1.X509BundlesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(resp.Bundles[td]); got != string(local.CACertDER()) {
		t.Errorf("own bundle missing or wrong under key %q; keys: %v", td, keys(resp.Bundles))
	}
	if got := string(resp.Bundles["spiffe://fed.example.org"]); got != string(fed.CACertDER()) {
		t.Errorf("federated bundle missing or wrong; keys: %v", keys(resp.Bundles))
	}
}

func TestFetchX509SVIDIncludesFederatedBundlesAndHint(t *testing.T) {
	s, client := startServer(t)
	local := newCA(t, td)
	fed := newCA(t, "spiffe://fed.example.org")
	svid, err := local.IssueX509SVID(td + "/workload")
	if err != nil {
		t.Fatal(err)
	}
	svid.Hint = "internal"
	s.SetX509State(&X509State{
		Materials:        []*ca.X509SVIDMaterial{svid},
		FederatedBundles: map[string][][]byte{"spiffe://fed.example.org": {fed.CACertDER()}},
	})

	stream, err := client.FetchX509SVID(withHeader(t), &workloadv1.X509SVIDRequest{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if resp.Svids[0].Hint != "internal" {
		t.Errorf("hint = %q, want internal", resp.Svids[0].Hint)
	}
	if _, ok := resp.FederatedBundles["spiffe://fed.example.org"]; !ok {
		t.Errorf("federated bundle missing; keys: %v", keys(resp.FederatedBundles))
	}
}

func TestFetchJWTBundlesStreamsUpdates(t *testing.T) {
	s, client := startServer(t)
	s.SetJWTState(&JWTState{Bundles: map[string][]byte{td: []byte(`{"keys":[]}`)}})

	stream, err := client.FetchJWTBundles(withHeader(t), &workloadv1.JWTBundlesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Bundles[td]) != `{"keys":[]}` {
		t.Fatalf("first bundle = %q", first.Bundles[td])
	}

	s.SetJWTState(&JWTState{Bundles: map[string][]byte{td: []byte(`{"keys":[1]}`)}})
	second, err := stream.Recv()
	if err != nil {
		t.Fatalf("no update streamed after SetJWTState: %v", err)
	}
	if string(second.Bundles[td]) != `{"keys":[1]}` {
		t.Fatalf("second bundle = %q", second.Bundles[td])
	}
}

func TestInjectErrorFailsGivenNumberOfCalls(t *testing.T) {
	s, client := startServer(t)
	c := newCA(t, td)
	tok, err := c.IssueJWT(td + "/workload")
	if err != nil {
		t.Fatal(err)
	}
	s.SetJWTState(&JWTState{Materials: []*ca.JWTSVIDMaterial{tok}})
	s.InjectError(MethodFetchJWTSVID, codes.Unavailable, 2)

	req := &workloadv1.JWTSVIDRequest{Audience: []string{"a"}}
	for i := 0; i < 2; i++ {
		if _, err := client.FetchJWTSVID(withHeader(t), req); status.Code(err) != codes.Unavailable {
			t.Fatalf("call %d: got %v, want Unavailable", i, err)
		}
	}
	resp, err := client.FetchJWTSVID(withHeader(t), req)
	if err != nil {
		t.Fatalf("call 3: %v", err)
	}
	if resp.Svids[0].Svid != tok.Token {
		t.Fatal("unexpected token")
	}
}

func TestFetchJWTSVIDPermissionDeniedWithoutMaterials(t *testing.T) {
	_, client := startServer(t)
	_, err := client.FetchJWTSVID(withHeader(t), &workloadv1.JWTSVIDRequest{Audience: []string{"a"}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v, want PermissionDenied", err)
	}
}

func TestCloseStreamsTerminatesWithCode(t *testing.T) {
	s, client := startServer(t)
	c := newCA(t, td)
	svid, err := c.IssueX509SVID(td + "/workload")
	if err != nil {
		t.Fatal(err)
	}
	s.SetX509State(&X509State{Materials: []*ca.X509SVIDMaterial{svid}})

	stream, err := client.FetchX509SVID(withHeader(t), &workloadv1.X509SVIDRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	s.CloseStreams(codes.Unavailable)
	if _, err := stream.Recv(); status.Code(err) != codes.Unavailable {
		t.Fatalf("got %v, want Unavailable", err)
	}
}

func TestValidateJWTSVID(t *testing.T) {
	s, client := startServer(t)
	c := newCA(t, td)
	jwks, err := c.JWKSBytes()
	if err != nil {
		t.Fatal(err)
	}
	s.SetJWTState(&JWTState{Bundles: map[string][]byte{td: jwks}})

	good, err := c.IssueJWT(td+"/workload", ca.WithJWTAudience("conformance"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.ValidateJWTSVID(withHeader(t), &workloadv1.ValidateJWTSVIDRequest{Audience: "conformance", Svid: good.Token})
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if resp.SpiffeId != td+"/workload" || resp.Claims.Fields["sub"].GetStringValue() != td+"/workload" {
		t.Fatalf("unexpected response: %v", resp)
	}

	_, err = client.ValidateJWTSVID(withHeader(t), &workloadv1.ValidateJWTSVIDRequest{Audience: "other", Svid: good.Token})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("wrong-audience token: got %v, want InvalidArgument", err)
	}
	if got := s.Calls(); len(got) != 2 || got[0].Method != MethodValidateJWTSVID {
		t.Fatalf("calls not recorded: %+v", got)
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRawX509ResponseIsSentVerbatim(t *testing.T) {
	s, client := startServer(t)
	c := newCA(t, td)
	svid, err := c.IssueX509SVID(td + "/workload")
	if err != nil {
		t.Fatal(err)
	}
	valid := &X509State{Materials: []*ca.X509SVIDMaterial{svid}}
	raw, err := BuildX509Response(valid)
	if err != nil {
		t.Fatal(err)
	}
	raw.Svids[0].Bundle = nil
	s.SetX509State(&X509State{Raw: raw})

	stream, err := client.FetchX509SVID(withHeader(t), &workloadv1.X509SVIDRequest{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Svids) != 1 || resp.Svids[0].Bundle != nil || resp.Svids[0].SpiffeId != td+"/workload" {
		t.Fatalf("unexpected response: %v", resp)
	}
}
