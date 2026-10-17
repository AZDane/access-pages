package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	connectorshare "github.com/layervai/qurl-connector/pkg/share"
	qurl "github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-integrations/apps/cli/internal/apitest"
	"github.com/layervai/qurl-integrations/apps/cli/internal/connector/agent"
)

const compatibilityID = "ha-page-0123456789abcdef0123456789abcdef01234567"

func compatibilityPublish(t *testing.T, srv *apitest.Server, id string, flags ...string) *runOpts {
	t.Helper()
	resolver := func(_ context.Context, _ *connectorshare.NativeRuntimeConfig, resolveID func(string) (string, error)) (*agent.ResolvedResource, error) {
		resolvedID, err := resolveID("agent-one")
		if err != nil {
			return nil, err
		}
		found := false
		return &agent.ResolvedResource{Resource: &qurl.ConnectorResource{
			ResourcePublicKey: srv.Key.ResourceID, CRID: srv.Key.CRID, Slug: resolvedID,
			ConnectorRoutingID: "c-" + strings.Repeat("a", 52), KnockResourceID: "q_catalog_key",
		}, FoundExisting: &found}, nil
	}
	opts := localPublish(t, srv, resolver, append([]string{"--id", id, "-o", "json"}, flags...)...)
	opts.env["ACCESS_PAGES_LEGACY_PUBLIC_PUBLISH"] = "1"
	return opts
}

func compatibilityDetail(t *testing.T, srv *apitest.Server, changes map[string]any) {
	t.Helper()
	srv.Script(http.MethodGet, "/v1/resources/"+srv.Key.CRID, func(w http.ResponseWriter, _ *http.Request) {
		row := map[string]any{"resource_id": srv.Key.ResourceID, "crid": srv.Key.CRID, "type": "tunnel", "status": "active", "desired_state": "off"}
		for key, value := range changes {
			row[key] = value
		}
		apitest.WriteEnvelope(t, w, http.StatusOK, map[string]any{"resource": row}, nil)
	})
}

func TestAccessPagesCompatibilityPublishesOnlyRequestedPublicResources(t *testing.T) {
	for _, isolation := range []string{"page", "guest"} {
		for _, privacy := range []any{nil, false} {
			t.Run(fmt.Sprintf("%s/privacy=%v", isolation, privacy), func(t *testing.T) {
				srv := apitest.NewServer(t)
				changes := map[string]any{}
				if privacy != nil {
					changes["private"] = privacy
				}
				compatibilityDetail(t, srv, changes)
				path := "/v1/resources/" + srv.Key.CRID + "/sharing"
				srv.Script(http.MethodGet, path, sharingResponse(t, srv, "off", 0, "stopped"))
				srv.Script(http.MethodPut, path, sharingResponse(t, srv, "on", 1, "connecting"))
				srv.Script(http.MethodGet, path, sharingResponse(t, srv, "on", 1, "serving"))
				id := strings.Replace(compatibilityID, "ha-page-", "ha-"+isolation+"-", 1)
				res := runCLI(t, compatibilityPublish(t, srv, id, "--public"))
				if res.code != 0 {
					t.Fatalf("publish failed: %s", res.stderr.String())
				}
				if len(createRequests(t, srv)) != 0 {
					t.Fatal("compatibility sent the incompatible REST create")
				}
				if privacy == nil && strings.Contains(res.stdout.String(), `"private": false`) {
					t.Fatal("invented a privacy confirmation")
				}
			})
		}
	}
}

func TestAccessPagesCompatibilityRejectsRestrictedOrMismatchedReadBack(t *testing.T) {
	for name, changes := range map[string]map[string]any{
		"private":         {"private": true},
		"access requests": {"access_requests": true},
		"device grants":   {"allowed_device_keys": []string{"recipient"}},
		"wrong identity":  {"crid": "wrong-resource"},
		"wrong type":      {"type": "url"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := apitest.NewServer(t)
			compatibilityDetail(t, srv, changes)
			res := runCLI(t, compatibilityPublish(t, srv, compatibilityID, "--public"))
			if res.code == 0 {
				t.Fatal("accepted unsafe read-back")
			}
			mustEmptyStdout(t, res)
			for _, request := range srv.Requests() {
				if request.Method != http.MethodGet {
					t.Fatalf("mutated serving state after rejected read-back: %s %s", request.Method, request.Path)
				}
			}
		})
	}
}

func TestAccessPagesCompatibilityRejectsPrivateAndUnscopedRequests(t *testing.T) {
	for _, tc := range []struct {
		id    string
		flags []string
	}{
		{compatibilityID, nil},
		{compatibilityID, []string{"--allow-requests"}},
		{compatibilityID, []string{"--allow-device-key", "cHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHA="}},
		{"unrelated-app", []string{"--public"}},
		{"ha-page-short", []string{"--public"}},
	} {
		t.Run(fmt.Sprint(tc), func(t *testing.T) {
			srv := apitest.NewServer(t)
			opts := compatibilityPublish(t, srv, tc.id, tc.flags...)
			opts.localResource = func(context.Context, *connectorshare.NativeRuntimeConfig, func(string) (string, error)) (*agent.ResolvedResource, error) {
				t.Fatal("native resource creation reached for rejected request")
				return nil, nil
			}
			res := runCLI(t, opts)
			if res.code == 0 || len(srv.Requests()) != 0 {
				t.Fatalf("rejected request did not fail before cloud mutation: %s", res.stderr.String())
			}
		})
	}
}

func TestAccessPagesCompatibilityStopsOnNativeFailureOrIdentityMismatch(t *testing.T) {
	for _, failure := range []string{"native error", "missing resource", "wrong slug", "skipped identity callback"} {
		t.Run(failure, func(t *testing.T) {
			srv := apitest.NewServer(t)
			opts := compatibilityPublish(t, srv, compatibilityID, "--public")
			original := opts.localResource
			opts.localResource = func(ctx context.Context, cfg *connectorshare.NativeRuntimeConfig, resolveID func(string) (string, error)) (*agent.ResolvedResource, error) {
				if failure == "native error" {
					return nil, errors.New("synthetic native refusal")
				}
				if failure == "skipped identity callback" {
					return &agent.ResolvedResource{Resource: &qurl.ConnectorResource{Slug: compatibilityID}}, nil
				}
				resource, err := original(ctx, cfg, resolveID)
				if err != nil {
					return nil, err
				}
				if failure == "missing resource" {
					resource.Resource = nil
				} else {
					resource.Resource.Slug = "other-resource"
				}
				return resource, nil
			}
			res := runCLI(t, opts)
			if res.code == 0 || len(srv.Requests()) != 0 {
				t.Fatalf("native failure reached read-back or serving: %s", res.stderr.String())
			}
			mustEmptyStdout(t, res)
		})
	}
}

func TestAccessPagesCompatibilityDoesNotServeAfterReadBackFailure(t *testing.T) {
	srv := apitest.NewServer(t)
	srv.Script(http.MethodGet, "/v1/resources/"+srv.Key.CRID, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	res := runCLI(t, compatibilityPublish(t, srv, compatibilityID, "--public"))
	if res.code == 0 {
		t.Fatal("read-back refusal was ignored")
	}
	mustEmptyStdout(t, res)
	for _, request := range srv.Requests() {
		if request.Method != http.MethodGet {
			t.Fatal("read-back failure mutated serving state")
		}
	}
}
