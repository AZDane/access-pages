package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxBodyBytes = 512_000
const maxGuestHeaders = 64
const maxGuestHeaderBytes = 32 * 1024
const maxActiveGuestRequests = 64
const guestSocket = "/run/access-pages/guest/http.sock"

type endpoint struct {
	pageID     string
	capability string
	proxy      *httputil.ReverseProxy
	slots      chan struct{}
}

var grantID = regexp.MustCompile(`^grant_[A-Za-z0-9_-]{16}$`)
var routeID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

var staticPaths = map[string]bool{
	"/static/access.css":                        true,
	"/static/access.js":                         true,
	"/static/access-api.js":                     true,
	"/static/home-assistant.png":                true,
	"/static/access-pages-mark.png":             true,
	"/static/access-pages-wordmark.png":         true,
	"/static/guest-access-lockup.png":           true,
	"/static/guest-access-mark-transparent.png": true,
	"/static/layerv.png":                        true,
	"/static/layerv-wordmark.png":               true,
}

func requiredEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		log.Fatalf("missing required environment variable: %s", name)
	}
	return value
}

func allowedGuestServicePath(pageID, path string) bool {
	if staticPaths[path] {
		return true
	}
	if !strings.HasPrefix(path, "/g/"+pageID+"/") || strings.ContainsAny(path, "%\\") {
		return false
	}
	for _, char := range path {
		if char > 127 {
			return false
		}
	}
	parts := strings.Split(strings.TrimPrefix(path, "/g/"+pageID+"/"), "/")
	if len(parts) < 2 || !grantID.MatchString(parts[0]) {
		return false
	}
	suffix := strings.Join(parts[1:], "/")
	if suffix == "" || staticPaths["/"+suffix] {
		return true
	}
	api := "api/access/" + pageID
	if suffix == api {
		return true
	}
	if len(parts) != 6 || parts[1] != "api" || parts[2] != "access" || parts[3] != pageID {
		return false
	}
	if parts[4] == "camera" || parts[4] == "verification" {
		return (parts[4] == "camera" && routeID.MatchString(parts[5])) ||
			(parts[4] == "verification" && (parts[5] == "send" || parts[5] == "verify"))
	}
	return routeID.MatchString(parts[4]) && routeID.MatchString(parts[5])
}

func (e *endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started, clockError := bootNanos()
	clientContext := r.Context()
	requestID := opaqueID()
	operation := guestOperation(r.Method, r.URL.Path, r.URL.Query().Has("bootstrap"))
	trace := newRequestTrace()
	r = r.WithContext(context.WithValue(r.Context(), requestTraceKey{}, trace))
	observed := &observedResponse{ResponseWriter: w}
	w = observed
	w.Header().Set(requestIDHeader, requestID)
	if operation != "asset" && r.URL.Path != "/health" {
		if detailedAt(started) {
			diagnostics.emit(diagnostic{RequestID: requestID, Operation: operation, At: "received", detail: true})
		}
		defer func() {
			failure := recover()
			ended, _ := bootNanos()
			elapsed := max(0, (ended-started)/int64(time.Millisecond))
			outcome := "ok"
			if observed.status >= 500 || trace.stages[11] != 0 {
				outcome = "error"
			}
			if elapsed >= 5000 {
				outcome = "slow"
			}
			if trace.stages[11] == 3 {
				outcome = "deadline"
			}
			if observed.failed || clientContext.Err() != nil || failure != nil {
				outcome = "disconnect"
			}
			if (operation == "action" || trace.stages[10] == 2) && outcome != "ok" && trace.stages[10] != 1 && trace.stages[10] != 3 {
				outcome = "uncertain"
			}
			if outcome != "ok" || detailedAt(ended) {
				diagnostics.emit(diagnostic{At: "end", RequestID: requestID, Operation: operation,
					ElapsedMS: min(diagnosticLimit, elapsed), Status: observed.status,
					Outcome: outcome, Stages: trace.stages, detail: outcome == "ok"})
			}
			if failure != nil {
				panic(failure)
			}
		}()
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none';")
	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	if clockError != nil {
		http.Error(w, "guest service unavailable", http.StatusServiceUnavailable)
		return
	}
	// Host is separate from Header in net/http but counted by the old gateway.
	headerCount, headerBytes := 1, len("Host")+len(r.Host)+4
	for name, values := range r.Header {
		for _, value := range values {
			headerCount++
			headerBytes += len(name) + len(value) + 4
		}
	}
	if headerCount > maxGuestHeaders || headerBytes > maxGuestHeaderBytes {
		http.Error(w, "request headers are too large", http.StatusRequestHeaderFieldsTooLarge)
		return
	}
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		http.Error(w, "guest service busy", http.StatusServiceUnavailable)
		return
	}
	if !allowedGuestServicePath(e.pageID, r.URL.Path) || r.URL.RawPath != "" || r.URL.IsAbs() {
		http.NotFound(w, r)
		return
	}
	if r.ContentLength > maxBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	for name := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-admin-") ||
			strings.HasPrefix(lower, "x-ingress-") ||
			strings.HasPrefix(lower, "x-page-") ||
			strings.HasPrefix(lower, "x-access-pages-") ||
			strings.HasPrefix(lower, "x-broker-") ||
			strings.HasPrefix(lower, "x-ha-") ||
			strings.HasPrefix(lower, "x-internal-") ||
			strings.HasPrefix(lower, "x-guest-service-") ||
			strings.HasPrefix(lower, "x-policy-") ||
			strings.HasPrefix(lower, "x-forwarded-") ||
			lower == "forwarded" || lower == "proxy-authorization" ||
			lower == "authorization" || lower == "x-real-ip" {
			r.Header.Del(name)
		}
	}
	r.Header.Set("X-Access-Pages-Page-ID", e.pageID)
	r.Header.Set("X-Page-Capability", e.capability)
	r.Header.Set(requestIDHeader, requestID)
	r.Header.Set(startedHeader, strconv.FormatInt(started, 10))
	if operation == "action" {
		now, err := bootNanos()
		if err != nil || now-started >= int64(actionLifetime) {
			http.Error(w, "guest request timed out", http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), actionLifetime-time.Duration(now-started))
		defer cancel()
		r = r.WithContext(ctx)
	}
	e.proxy.ServeHTTP(w, r)
}

func guestOperation(method, path string, bootstrap bool) string {
	parts := strings.Split(path, "/")
	if method == http.MethodGet && ((len(parts) == 3 && parts[1] == "static") ||
		(len(parts) == 6 && parts[1] == "g" && parts[4] == "static")) {
		return "asset"
	}
	if len(parts) < 5 || parts[1] != "g" {
		return "other"
	}
	if len(parts) == 5 && parts[4] == "" {
		if bootstrap {
			return "bootstrap"
		}
		return "document"
	}
	if method == http.MethodGet && len(parts) == 7 && parts[4] == "api" && parts[5] == "access" {
		return "state"
	}
	if len(parts) == 9 && parts[4] == "api" && parts[5] == "access" {
		if method == http.MethodGet && parts[7] == "camera" {
			return "camera"
		}
		if method == http.MethodPost {
			// Payload validation in the guest service resolves these ambiguous routes.
			if parts[7] == "verification" && (parts[8] == "send" || parts[8] == "verify") {
				return "other"
			}
			return "action"
		}
	}
	return "other"
}

func newGuestServiceProxy(socketPath string, uid, gid, socketGID uint32) *httputil.ReverseProxy {
	upstream := &url.URL{Scheme: "http", Host: "guest-service"}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	proxy.ModifyResponse = captureDiagnosticStages
	originalDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		originalDirector(request)
		request.Host = upstream.Host
		request.Header["X-Forwarded-For"] = nil
	}
	proxy.Transport = &http.Transport{
		DisableKeepAlives: true, // Recheck the path and peer after each restart.
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			info, err := os.Lstat(socketPath)
			if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("guest service socket unavailable")
			}
			owner, ok := info.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != uid || owner.Gid != socketGID || info.Mode().Perm() != 0o660 {
				return nil, errors.New("guest service socket identity mismatch")
			}
			conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socketPath)
			if err != nil {
				return nil, err
			}
			unixConn, ok := conn.(*net.UnixConn)
			if !ok {
				conn.Close()
				return nil, errors.New("not a Unix connection")
			}
			raw, err := unixConn.SyscallConn()
			if err == nil {
				var peerErr error
				err = raw.Control(func(fd uintptr) {
					peer, lookupErr := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
					if lookupErr != nil || peer.Uid != uid || peer.Gid != gid {
						peerErr = errors.New("guest service peer identity mismatch")
					}
				})
				if err == nil {
					err = peerErr
				}
			}
			if err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, _ error) {
		status := http.StatusBadGateway
		if errors.Is(r.Context().Err(), context.DeadlineExceeded) {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, "guest service unavailable", status)
	}
	return proxy
}

func main() {
	pageID := requiredEnv("GATEWAY_BOUND_PAGE_ID")
	capability := requiredEnv("PAGE_CAPABILITY_TOKEN")
	host := requiredEnv("HOST")
	port, err := strconv.Atoi(requiredEnv("PORT"))
	if err != nil || port < 1 || port > 65535 {
		log.Fatal("invalid PORT")
	}
	if requiredEnv("GUEST_ENDPOINT_GUEST_SERVICE_SOCKET") != guestSocket {
		log.Fatal("invalid guest service socket")
	}
	proxy := newGuestServiceProxy(guestSocket, 2101, 2101, 2004)
	server := &http.Server{
		Addr:              host + ":" + strconv.Itoa(port),
		Handler:           &endpoint{pageID: pageID, capability: capability, proxy: proxy, slots: make(chan struct{}, maxActiveGuestRequests)},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    maxGuestHeaderBytes,
	}
	log.Printf("Access Pages page endpoint listening on http://%s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
