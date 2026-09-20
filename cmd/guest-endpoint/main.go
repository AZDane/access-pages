package main

import (
	"context"
	"encoding/json"
	"errors"
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
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none';")
	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
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
	e.proxy.ServeHTTP(w, r)
}

func newGuestServiceProxy(socketPath string, uid, gid, socketGID uint32) *httputil.ReverseProxy {
	upstream := &url.URL{Scheme: "http", Host: "guest-service"}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
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
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		log.Printf("guest service unavailable")
		http.Error(w, "guest service unavailable", http.StatusBadGateway)
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
