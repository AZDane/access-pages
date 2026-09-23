package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

func TestActionTimingStartsAtGatewayAndCannotBeForged(t *testing.T) {
	upstream, _ := url.Parse("http://guest-service")
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	ids := make(map[string]bool)
	proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		id := r.Header.Get(requestIDHeader)
		if len(id) != 32 || ids[id] || id == strings.Repeat("a", 32) {
			t.Fatal("request ID was reused or trusted from client")
		}
		ids[id] = true
		start, err := strconv.ParseInt(r.Header.Get(startedHeader), 10, 64)
		now, _ := bootNanos()
		if err != nil || start <= 0 || now-start < 0 || now-start > int64(time.Second) {
			t.Fatal("request lifetime did not originate at this Gateway")
		}
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > actionLifetime || time.Until(deadline) < 7*time.Second {
			t.Fatal("action has no eight-second Gateway budget")
		}
		if r.Header.Get("X-Access-Pages-Operation") != "" || r.Header.Get("X-Access-Pages-Rpc-Started-Ns") != "" {
			t.Fatal("client forged internal timing context")
		}
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: http.NoBody}, nil
	})
	handler := &endpoint{pageID: "airbnb", capability: "page-secret", proxy: proxy,
		slots: make(chan struct{}, maxActiveGuestRequests)}
	for range 2 {
		r := httptest.NewRequest(http.MethodPost, "/g/airbnb/grant_mmmmmmmmmmmmmmmm/api/access/airbnb/light/turn_on", strings.NewReader("{}"))
		r.Header.Set(requestIDHeader, strings.Repeat("a", 32))
		r.Header.Set(startedHeader, "9999999999999999999")
		r.Header.Set("X-Access-Pages-Rpc-Started-Ns", "9999999999999999999")
		r.Header.Set("X-Access-Pages-Operation", "state")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		if response.Code != 204 || !ids[response.Header().Get(requestIDHeader)] {
			t.Fatal("response lost correlation")
		}
	}
}

func TestOpaqueRouteIdentifiersAndActualAssets(t *testing.T) {
	for _, page := range []string{"static", "camera", "api", "health", "verification", "g", "access"} {
		root := "/g/" + page + "/grant_mmmmmmmmmmmmmmmm/"
		api := root + "api/access/" + page
		for path, expected := range map[string]string{root: "document", api: "state", root + "static/access.js": "asset", "/static/access.js": "asset"} {
			if !allowedGuestServicePath(page, path) || guestOperation("GET", path, false) != expected {
				t.Fatalf("%s: unexpected classification", path)
			}
		}
		for _, resource := range []string{"static", "camera", "state", "action", "api", "health", "verification"} {
			if guestOperation("GET", api+"/camera/"+resource, false) != "camera" {
				t.Fatal("camera route not recognized")
			}
			for _, action := range []string{"static", "camera", "state", "action", "turn_on"} {
				if got := guestOperation("POST", api+"/"+resource+"/"+action, false); got != "action" {
					t.Fatalf("%s/%s: %s", resource, action, got)
				}
			}
		}
		for _, action := range []string{"send", "verify"} {
			path := api + "/verification/" + action
			if !allowedGuestServicePath(page, path) || guestOperation("POST", path, false) != "other" {
				t.Fatal("ambiguous route must await payload validation")
			}
		}
	}
}

func TestDiagnosticStagesAreNumericPrivateAndNonAuthorizing(t *testing.T) {
	for _, header := range []string{"1,2,3,4,5,6,7,1,2,1,1,0", "cookie=private", strings.Repeat("1,", 10000), "1,2,3,4,5,600001,7,1,2,1,1,0"} {
		trace := newRequestTrace()
		request := httptest.NewRequest("GET", "/", nil)
		request = request.WithContext(context.WithValue(request.Context(), requestTraceKey{}, trace))
		response := &http.Response{Request: request, Header: make(http.Header)}
		response.Header.Set(stagesHeader, header)
		if captureDiagnosticStages(response) != nil {
			t.Fatal("diagnostics changed request outcome")
		}
		if response.Header.Get(stagesHeader) != "" {
			t.Fatal("internal stages leaked downstream")
		}
		if header == "1,2,3,4,5,6,7,1,2,1,1,0" {
			if len(trace.stages) != 12 || trace.stages[5] != 6 {
				t.Fatal("valid timing lost")
			}
		} else if trace.stages[0] != -1 {
			t.Fatal("invalid diagnostic accepted")
		}
	}
}

type disconnectedWriter struct{ *httptest.ResponseRecorder }

func (w disconnectedWriter) Write(_ []byte) (int, error) { return 0, syscall.EPIPE }

func TestStateDownstreamDisconnectRetainsUpstreamStages(t *testing.T) {
	proxy := newGuestServiceProxy("unused", 0, 0, 0)
	var trace *requestTrace
	proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		trace = r.Context().Value(requestTraceKey{}).(*requestTrace)
		headers := make(http.Header)
		headers.Set(stagesHeader, "10,20,30,40,50,60,70,1,10,1,1,0")
		return &http.Response{Request: r, StatusCode: 200, Header: headers, Body: io.NopCloser(strings.NewReader("state"))}, nil
	})
	handler := &endpoint{pageID: "static", capability: "synthetic", proxy: proxy, slots: make(chan struct{}, maxActiveGuestRequests)}
	writer := disconnectedWriter{httptest.NewRecorder()}
	handler.ServeHTTP(writer, httptest.NewRequest("GET", "/g/static/grant_mmmmmmmmmmmmmmmm/api/access/static", nil))
	if trace == nil || len(trace.stages) != 12 || trace.stages[4] != 50 {
		t.Fatal("late downstream disconnect lost successful upstream evidence")
	}
	if writer.Header().Get(stagesHeader) != "" {
		t.Fatal("private timing exposed")
	}
}

func TestHealthyPollingSilentAndSlowThreshold(t *testing.T) {
	original := diagnostics
	diagnostics = &diagnosticSink{queue: make(chan diagnostic, 16)}
	defer func() { diagnostics = original }()
	proxy := newGuestServiceProxy("unused", 0, 0, 0)
	proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{Request: r, StatusCode: 200, Header: make(http.Header), Body: http.NoBody}, nil
	})
	handler := &endpoint{pageID: "guest", capability: "synthetic", proxy: proxy, slots: make(chan struct{}, 64)}
	for range 1200 {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/g/guest/grant_mmmmmmmmmmmmmmmm/api/access/guest", nil))
	}
	if len(diagnostics.queue) != 0 || diagnostics.lost.Load() != 0 {
		t.Fatal("healthy polling emitted diagnostics")
	}
	proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		time.Sleep(5 * time.Second)
		return &http.Response{Request: r, StatusCode: 200, Header: make(http.Header), Body: http.NoBody}, nil
	})
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/g/guest/grant_mmmmmmmmmmmmmmmm/api/access/guest", nil))
	record := <-diagnostics.queue
	if record.Outcome != "slow" || record.ElapsedMS < 5000 || len(record.RequestID) != 32 {
		t.Fatal("slow success not localized")
	}
}

func TestDiagnosticRateBudget(t *testing.T) {
	for _, detail := range []bool{false, true} {
		var budget diagnosticBudget
		count := 0
		for i := int64(0); i < int64(time.Hour); i += int64(time.Millisecond) {
			if budget.take(i, detail) {
				count++
			}
		}
		expected := 60
		if detail {
			expected = 1811
		}
		if count != expected {
			t.Fatalf("detail=%v count=%d expected=%d", detail, count, expected)
		}
	}
}

func TestDetailedPollingSpendsOnlyOneTokenOnCompleteVector(t *testing.T) {
	original, originalUntil := diagnostics, detailUntil
	defer func() { diagnostics, detailUntil = original, originalUntil }()
	now, _ := bootNanos()
	detailUntil = now + int64(time.Hour)
	diagnostics = &diagnosticSink{queue: make(chan diagnostic, 16)}
	proxy := newGuestServiceProxy("unused", 0, 0, 0)
	proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		headers := make(http.Header)
		headers.Set(stagesHeader, "1,2,3,4,5,6,7,1,1,1,1,0")
		return &http.Response{Request: r, StatusCode: 200, Header: headers, Body: http.NoBody}, nil
	})
	handler := &endpoint{pageID: "guest", capability: "synthetic", proxy: proxy, slots: make(chan struct{}, 64)}
	for range 100 {
		now, _ = bootNanos()
		// Only one token remains: an early receipt must not steal the final's slot.
		diagnostics.admission = diagnosticBudget{tokens: 1, last: now, mode: true, initialized: true}
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/g/guest/grant_mmmmmmmmmmmmmmmm/api/access/guest", nil))
		if len(diagnostics.queue) != 1 || diagnostics.lost.Load() != 0 {
			t.Fatal("ordinary completed request did not retain exactly one summary")
		}
		record := <-diagnostics.queue
		if record.At != "end" || record.Status != 200 || record.Outcome != "ok" || record.Stages[6] != 7 || len(record.RequestID) != 32 {
			t.Fatalf("incomplete final summary: %+v", record)
		}
	}
}

type blockedDiagnosticWriter struct {
	entered chan bool
	release chan bool
}

func (w blockedDiagnosticWriter) Write(b []byte) (int, error) {
	select {
	case w.entered <- true:
	default:
	}
	<-w.release
	return len(b), nil
}

func TestBlockedDiagnosticOutputCannotDelayRequests(t *testing.T) {
	writer := blockedDiagnosticWriter{make(chan bool, 1), make(chan bool)}
	sink := newDiagnosticSink(writer)
	defer close(writer.release)
	sink.emit(diagnostic{At: "end"})
	<-writer.entered
	start := time.Now()
	for range 10000 {
		sink.emit(diagnostic{At: "end"})
	}
	if time.Since(start) > time.Second || sink.lost.Load() < 9980 || cap(sink.queue) != 16 {
		t.Fatal("unbounded logging")
	}
}

func TestClosedStderrDoesNotTerminateGateway(t *testing.T) {
	if os.Getenv("AP_TEST_CLOSED_STDERR") == "1" {
		// Go normally terminates on SIGPIPE when descriptor 2 has no reader.
		if _, err := os.Stderr.Write([]byte("synthetic diagnostic\n")); err == nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	defer writer.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestClosedStderrDoesNotTerminateGateway$")
	child.Env = append(os.Environ(), "AP_TEST_CLOSED_STDERR=1")
	child.Stderr = writer
	if err := child.Run(); err != nil {
		t.Fatal("closed logging output terminated process:", err)
	}
}

func TestDeadlineSummaryRequiresPositiveNoDispatchEvidence(t *testing.T) {
	original := diagnostics
	defer func() { diagnostics = original }()
	for _, dispatch := range []int{0, 1, 2} {
		diagnostics = &diagnosticSink{queue: make(chan diagnostic, 16)}
		proxy := newGuestServiceProxy("unused", 0, 0, 0)
		proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			headers := make(http.Header)
			headers.Set(stagesHeader, "0,1,2,-1,-1,3,4,0,0,1,"+strconv.Itoa(dispatch)+",3")
			return &http.Response{Request: r, StatusCode: 503, Header: headers, Body: http.NoBody}, nil
		})
		handler := &endpoint{pageID: "guest", capability: "synthetic", proxy: proxy, slots: make(chan struct{}, 64)}
		// This path can be a saved action after backend payload validation.
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/g/guest/grant_mmmmmmmmmmmmmmmm/api/access/guest/verification/send", strings.NewReader("{}")))
		record := <-diagnostics.queue
		expected := "uncertain"
		if dispatch == 1 {
			expected = "deadline"
		}
		if record.Outcome != expected {
			t.Fatalf("dispatch=%d outcome=%s", dispatch, record.Outcome)
		}
	}
}
