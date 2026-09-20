package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func testUnixServer(t *testing.T, path string, handler http.Handler) func() {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	return func() { server.Close(); os.Remove(path) }
}

func unixEndpoint(path string, uid, gid uint32) http.Handler {
	return &endpoint{pageID: "airbnb", capability: "page-secret",
		proxy: newGuestServiceProxy(path, uid, gid, uint32(os.Getgid())),
		slots: make(chan struct{}, maxActiveGuestRequests)}
}

func probe(handler http.Handler, path string, headers http.Header) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if headers == nil {
		headers = make(http.Header)
	}
	request.Header = headers
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestGuestServiceRoutesAndHeaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "http.sock")
	got := make(chan *http.Request, 2)
	stop := testUnixServer(t, path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Clone(context.Background())
		w.WriteHeader(http.StatusNoContent)
	}))
	defer stop()
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	handler := unixEndpoint(path, uid, gid)
	root := "/g/airbnb/grant_mmmmmmmmmmmmmmmm/"
	routes := []string{root, root + "api/access/airbnb", root + "api/access/airbnb/camera/front", root + "api/access/airbnb/verification/send", root + "api/access/airbnb/light/turn_on"}
	for asset := range staticPaths {
		routes = append(routes, asset, root+strings.TrimPrefix(asset, "/"))
	}
	for _, route := range routes {
		if response := probe(handler, route, nil); response.Code != http.StatusNoContent {
			t.Fatalf("%s: %d", route, response.Code)
		}
		<-got
	}
	headers := make(http.Header)
	for _, name := range []string{"X-Admin-Token", "X-Page-Capability", "X-Access-Pages-Page-ID", "X-Broker-Role", "X-HA-Token", "X-Policy-Token", "X-Forwarded-For", "Forwarded", "Authorization", "Proxy-Authorization", "X-Internal-Role"} {
		headers.Set(name, "attacker")
	}
	headers.Set("X-Guest-Request", "1")
	if response := probe(handler, root+"api/access/airbnb", headers); response.Code != http.StatusNoContent {
		t.Fatal(response.Code)
	}
	received := <-got
	for _, name := range []string{"X-Admin-Token", "X-Broker-Role", "X-HA-Token", "X-Policy-Token", "X-Forwarded-For", "Forwarded", "Authorization", "Proxy-Authorization", "X-Internal-Role"} {
		if received.Header.Get(name) != "" {
			t.Fatalf("forged %s forwarded", name)
		}
	}
	if received.Header.Get("X-Access-Pages-Page-ID") != "airbnb" || received.Header.Get("X-Page-Capability") != "page-secret" || received.Header.Get("X-Guest-Request") != "1" {
		t.Fatal("trusted context or guest header incorrect")
	}
	for _, route := range []string{"/access/airbnb", "/api/access/airbnb", "/admin", "/api/admin/pages", "/api/admin/preview/airbnb", "/api/internal/guest-activity", "/discovery", "/notifications", "/policy", "/broker-page", "/g/other/grant_mmmmmmmmmmmmmmmm/", root + "api/admin", root + "api/admin/preview/airbnb", root + "api/access/other", root + "../admin", root + "static/../../admin"} {
		if response := probe(handler, route, nil); response.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", route, response.Code)
		}
	}
	absolute := httptest.NewRequest(http.MethodGet, "http://attacker.invalid"+root, nil)
	absolute.URL.Scheme, absolute.URL.Host = "http", "attacker.invalid"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, absolute)
	if response.Code != http.StatusNotFound {
		t.Fatal("absolute proxy URL accepted")
	}
}

func TestGuestServiceSocketIdentityAndRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "http.sock")
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	handler := unixEndpoint(path, uid, gid)
	route := "/g/airbnb/grant_mmmmmmmmmmmmmmmm/"
	if response := probe(handler, route, nil); response.Code != http.StatusBadGateway {
		t.Fatal("missing socket did not fail closed")
	}
	stop := testUnixServer(t, path, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	if response := probe(handler, route, nil); response.Code != 204 {
		t.Fatal("valid peer rejected")
	}
	if response := probe(unixEndpoint(path, uid+1, gid), route, nil); response.Code != 502 {
		t.Fatal("wrong UID accepted")
	}
	if response := probe(unixEndpoint(path, uid, gid+1), route, nil); response.Code != 502 {
		t.Fatal("wrong GID accepted")
	}
	stop()
	if response := probe(handler, route, nil); response.Code != 502 {
		t.Fatal("stopped service did not fail closed")
	}
	target := filepath.Join(dir, "target.sock")
	stopTarget := testUnixServer(t, target, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer stopTarget()
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if response := probe(handler, route, nil); response.Code != 502 {
		t.Fatal("symlink accepted")
	}
	os.Remove(path)
	stop = testUnixServer(t, path, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(201) }))
	defer stop()
	if response := probe(handler, route, nil); response.Code != 201 {
		t.Fatal("restart did not reconnect")
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if response := probe(handler, route, nil); response.Code != 502 {
		t.Fatal("replaced socket permissions accepted")
	}
	if strings.Contains(probe(handler, route, nil).Body.String(), path) {
		t.Fatal("socket path leaked")
	}
}

func TestGuestServiceMidRequestFailureHasNoFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "http.sock")
	stop := testUnixServer(t, path, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		connection, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			connection.Close()
		}
	}))
	defer stop()
	handler := unixEndpoint(path, uint32(os.Getuid()), uint32(os.Getgid()))
	response := probe(handler, "/g/airbnb/grant_mmmmmmmmmmmmmmmm/", nil)
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), path) {
		t.Fatalf("mid-request failure leaked or fell back: %d %s", response.Code, response.Body.String())
	}
}

func TestGuestHTTPGuardsOnActiveEndpoint(t *testing.T) {
	root := "/g/airbnb/grant_mmmmmmmmmmmmmmmm/"
	upstream, _ := url.Parse("http://guest-service")
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	var forwarded atomic.Int32
	proxy.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		forwarded.Add(1)
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: http.NoBody}, nil
	})
	handler := &endpoint{pageID: "airbnb", capability: "page-secret", proxy: proxy,
		slots: make(chan struct{}, maxActiveGuestRequests)}
	checkHeaders := func(response *httptest.ResponseRecorder) {
		t.Helper()
		for name, expected := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"Referrer-Policy":        "no-referrer",
			"Cache-Control":          "no-store",
		} {
			values := response.Header().Values(name)
			if len(values) != 1 || values[0] != expected {
				t.Fatalf("unexpected %s headers: %v", name, values)
			}
		}
		csp := response.Header().Values("Content-Security-Policy")
		if len(csp) != 1 || !strings.Contains(csp[0], "frame-ancestors 'none'") {
			t.Fatalf("unexpected guest CSP headers: %v", csp)
		}
		if len(response.Header().Values("Server")) != 0 {
			t.Fatalf("guest endpoint exposed Server: %v", response.Header().Values("Server"))
		}
	}
	checkHeaders(probe(handler, root, nil))
	if response := probe(handler, "/api/admin/pages", nil); response.Code != 404 {
		t.Fatalf("admin route: %d", response.Code)
	} else {
		checkHeaders(response)
	}
	headers := make(http.Header)
	for i := 0; i < 63; i++ {
		headers.Set("X-Example-"+strconv.Itoa(i), "1")
	}
	if response := probe(handler, root, headers); response.Code != 204 {
		t.Fatalf("64 total headers should pass: %d", response.Code)
	}
	headers.Set("X-Example-64", "1")
	if response := probe(handler, root, headers); response.Code != 431 {
		t.Fatalf("header count bypass: %d", response.Code)
	} else {
		checkHeaders(response)
	}
	if response := probe(handler, "/api/admin/pages", headers); response.Code != 431 {
		t.Fatalf("malformed admin path reached proxy: %d", response.Code)
	}
	large := http.Header{"X-Large": {strings.Repeat("x", maxGuestHeaderBytes)}}
	if response := probe(handler, root, large); response.Code != 431 {
		t.Fatalf("header byte limit bypass: %d", response.Code)
	}
	if forwarded.Load() != 2 {
		t.Fatalf("rejected requests reached guest service: %d", forwarded.Load())
	}
}

func TestGuestActiveRequestCeilingRecovers(t *testing.T) {
	root := "/g/airbnb/grant_mmmmmmmmmmmmmmmm/"
	upstream, _ := url.Parse("http://guest-service")
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	entered := make(chan struct{}, maxActiveGuestRequests)
	release := make(chan struct{})
	var forwarded atomic.Int32
	proxy.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		forwarded.Add(1)
		entered <- struct{}{}
		<-release
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: http.NoBody}, nil
	})
	handler := &endpoint{pageID: "airbnb", capability: "page-secret", proxy: proxy,
		slots: make(chan struct{}, maxActiveGuestRequests)}
	var workers sync.WaitGroup
	for i := 0; i < maxActiveGuestRequests; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if result := probe(handler, root, nil); result.Code != 204 {
				t.Errorf("in-flight request failed: %d", result.Code)
			}
		}()
	}
	for i := 0; i < maxActiveGuestRequests; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			workers.Wait()
			t.Fatal("guest requests did not fill the active ceiling")
		}
	}
	if result := probe(handler, root, nil); result.Code != 503 {
		t.Fatalf("overload did not fail closed: %d", result.Code)
	}
	if forwarded.Load() != maxActiveGuestRequests {
		t.Fatal("overload reached guest service")
	}
	if result := probe(handler, "/api/admin/pages", nil); result.Code != 503 {
		t.Fatalf("overloaded admin path reached proxy: %d", result.Code)
	}
	close(release)
	workers.Wait()
	if result := probe(handler, root, nil); result.Code != 204 {
		t.Fatalf("capacity did not return: %d", result.Code)
	}
}
