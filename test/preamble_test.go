package test

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cronet "github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

// Cases from the test plan in docs/naive-preamble-design.md §10.2.

const preamblePage = `<!doctype html>
<html><head>
<link rel="stylesheet" href="/style.css">
<script src="/app.js"></script>
</head><body>
<img src="/img/logo.png">
<a href="/about.html">about</a>
<link rel="stylesheet" href="https://other.example.org/x.css">
</body></html>`

// --- NetLog helpers -------------------------------------------------------

type netLogFile struct {
	Constants struct {
		LogEventTypes map[string]int `json:"logEventTypes"`
	} `json:"constants"`
	Events []netLogEvent `json:"events"`
}

type netLogEvent struct {
	Type   int    `json:"type"`
	Time   string `json:"time"`
	Source struct {
		ID   int `json:"id"`
		Type int `json:"type"`
	} `json:"source"`
	Params struct {
		Headers json.RawMessage `json:"headers"`
	} `json:"params"`
}

// netLogHeaders accepts both the flat list and the nested object form used by
// different NetLog events.
func netLogHeaders(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var object struct {
		Headers []string `json:"headers"`
	}
	if err := json.Unmarshal(raw, &object); err == nil {
		return object.Headers
	}
	return nil
}

type netLogStream struct {
	event       string
	session     int
	method      string
	path        string
	userAgent   string
	headerNames []string
	values      map[string]string
	hasPadding  bool
	hasAuth     bool
}

func parseNetLogStreams(t *testing.T, path string) []netLogStream {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var logFile netLogFile
	require.NoError(t, json.Unmarshal(data, &logFile))
	eventNames := make(map[int]string, len(logFile.Constants.LogEventTypes))
	for name, id := range logFile.Constants.LogEventTypes {
		eventNames[id] = name
	}
	var streams []netLogStream
	for _, event := range logFile.Events {
		name := eventNames[event.Type]
		var stream netLogStream
		switch name {
		case "HTTP2_SESSION_SEND_HEADERS":
			stream = netLogStream{
				event:   "h2",
				session: event.Source.ID,
			}
		case "QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS":
			stream = netLogStream{
				event:   "quic",
				session: event.Source.ID,
			}
		default:
			continue
		}
		for _, header := range netLogHeaders(event.Params.Headers) {
			name, value, found := strings.Cut(header, ": ")
			name = strings.ToLower(name)
			if !found {
				continue
			}
			if !strings.HasPrefix(name, ":") {
				stream.headerNames = append(stream.headerNames, name)
			}
			if stream.values == nil {
				stream.values = make(map[string]string)
			}
			stream.values[name] = value
			switch name {
			case ":method":
				stream.method = value
			case ":path":
				stream.path = value
			case "user-agent":
				stream.userAgent = value
			case "padding":
				stream.hasPadding = true
			case "proxy-authorization":
				stream.hasAuth = true
			}
		}
		streams = append(streams, stream)
	}
	return streams
}

func findStream(streams []netLogStream, method string, path string) int {
	for index, stream := range streams {
		if stream.method == method && (path == "" || stream.path == path) {
			return index
		}
	}
	return -1
}

func findStreamByPath(streams []netLogStream, path string) int {
	for index, stream := range streams {
		if stream.path == path {
			return index
		}
	}
	return -1
}

// setupTestEnvWithoutServer generates the test certificate only, for tests
// that bring their own fronting server.
func setupTestEnvWithoutServer(t *testing.T) *testEnv {
	t.Helper()
	caPem, certPem, keyPem := generateCertificate(t, "example.org")
	caPemContent, err := os.ReadFile(caPem)
	require.NoError(t, err)
	return &testEnv{caPEM: caPemContent, certPath: certPem, keyPath: keyPem}
}

func stopAndWaitNetLog(t *testing.T, client *cronet.NaiveClient) {
	t.Helper()
	client.Engine().StopNetLog()
	// Give the netlog a moment to flush the file.
	time.Sleep(200 * time.Millisecond)
}

// --- T5/T7/T11: preamble against a bare naive server ----------------------

func TestNaivePreamble(t *testing.T) {
	env := setupTestEnv(t)
	client := env.newNaiveClient(t, cronet.NaiveClientOptions{})
	netLogPath := startNetLogForTest(t, client, "preamble.json", true)

	echoPort := reserveTCPPort(t)
	startEchoServer(t, echoPort)

	dialCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := client.DialContext(dialCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	require.NoError(t, err)
	defer conn.Close()

	// A bare naive server answers the preamble with 400; the tunnel still works.
	payload := []byte("preamble-does-not-block")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	response := make([]byte, len(payload))
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	require.Equal(t, payload, response)

	stopAndWaitNetLog(t, client)
	streams := parseNetLogStreams(t, netLogPath)

	rootIndex := findStream(streams, "GET", "/")
	require.GreaterOrEqual(t, rootIndex, 0, "no preamble root request found in %v", streams)
	connectIndex := findStream(streams, "CONNECT", "")
	require.GreaterOrEqual(t, connectIndex, 0, "no CONNECT request found")
	require.Less(t, rootIndex, connectIndex, "the preamble root request must be sent before the CONNECT")

	root := streams[rootIndex]
	connect := streams[connectIndex]
	require.Equal(t, root.session, connect.session, "preamble and CONNECT must share one session")
	require.Equal(t, "h2", root.event)

	// Preamble requests carry no credentials and no padding.
	require.False(t, root.hasPadding, "preamble request must not send padding")
	require.False(t, root.hasAuth, "preamble request must not send proxy-authorization")
	require.Contains(t, root.userAgent, "Chrome/", "preamble request must send a browser user agent")
	require.Equal(t,
		[]string{
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
			"user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user",
			"sec-fetch-dest", "accept-encoding", "accept-language", "priority",
		},
		root.headerNames, "preamble headers must be sent in the native naive order")

	// The tunnel request has to carry a browser user agent too.
	require.True(t, connect.hasPadding, "CONNECT must send padding")
	require.True(t, connect.hasAuth, "CONNECT must send proxy-authorization")
	require.NotEmpty(t, connect.userAgent, "CONNECT must not send an empty user-agent")
	require.Contains(t, connect.userAgent, "Chrome/")
	require.Equal(t, "1", connect.values["padding-type-request"], "CONNECT must request padding variant 1")
	require.Equal(t, []string{"padding", "padding-type-request", "user-agent", "proxy-authorization"},
		connect.headerNames, "CONNECT headers must be sent in the native naive order")
}

// --- T6: preamble over QUIC ----------------------------------------------

func TestNaivePreambleQUIC(t *testing.T) {
	env := setupTestEnv(t)
	quicPort := reserveUDPPort(t)
	startNaiveQUICServer(t, env.certPath, env.keyPath, quicPort)

	client := env.newNaiveClient(t, cronet.NaiveClientOptions{
		ServerAddress: M.ParseSocksaddrHostPort("127.0.0.1", quicPort),
		QUIC:          true,
	})
	netLogPath := startNetLogForTest(t, client, "preamble-quic.json", true)

	echoPort := reserveTCPPort(t)
	startEchoServer(t, echoPort)

	dialCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	conn, err := client.DialContext(dialCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	require.NoError(t, err)
	defer conn.Close()
	payload := []byte("quic-preamble")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	response := make([]byte, len(payload))
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	require.Equal(t, payload, response)

	stopAndWaitNetLog(t, client)
	streams := parseNetLogStreams(t, netLogPath)
	rootIndex := findStream(streams, "GET", "/")
	connectIndex := findStream(streams, "CONNECT", "")
	require.GreaterOrEqual(t, rootIndex, 0, "no QUIC preamble request found in %v", streams)
	require.GreaterOrEqual(t, connectIndex, 0, "no QUIC CONNECT found")
	require.Less(t, rootIndex, connectIndex)
	require.Equal(t, "quic", streams[rootIndex].event, "preamble must be sent over QUIC")
	require.Equal(t, streams[rootIndex].session, streams[connectIndex].session,
		"preamble and CONNECT must share one QUIC session")
}

// --- T8/T9: fronting website with compressed pages ------------------------

type recordedRequest struct {
	method  string
	path    string
	headers map[string]string
}

type frontingSite struct {
	address string
	mutex   sync.Mutex
	records []recordedRequest
}

func (s *frontingSite) requests() []recordedRequest {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return append([]recordedRequest(nil), s.records...)
}

func (s *frontingSite) paths() []string {
	var paths []string
	for _, request := range s.requests() {
		paths = append(paths, request.method+" "+request.path)
	}
	return paths
}

func startFrontingSite(t *testing.T, env *testEnv, encoding string) *frontingSite {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(env.certPath, env.keyPath)
	require.NoError(t, err)

	site := &frontingSite{}
	compress := func(data []byte) []byte {
		switch encoding {
		case "zstd":
			writer, err := zstd.NewWriter(nil)
			require.NoError(t, err)
			return writer.EncodeAll(data, nil)
		case "br":
			buffer := &bytes.Buffer{}
			writer := brotli.NewWriter(buffer)
			_, _ = writer.Write(data)
			_ = writer.Close()
			return buffer.Bytes()
		case "gzip":
			buffer := &bytes.Buffer{}
			writer := gzip.NewWriter(buffer)
			_, _ = writer.Write(data)
			_ = writer.Close()
			return buffer.Bytes()
		case "deflate":
			buffer := &bytes.Buffer{}
			writer := zlib.NewWriter(buffer)
			_, _ = writer.Write(data)
			_ = writer.Close()
			return buffer.Bytes()
		}
		return data
	}

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		headers := make(map[string]string, len(request.Header))
		for name := range request.Header {
			headers[strings.ToLower(name)] = request.Header.Get(name)
		}
		site.mutex.Lock()
		site.records = append(site.records, recordedRequest{
			method:  request.Method,
			path:    request.URL.RequestURI(),
			headers: headers,
		})
		site.mutex.Unlock()

		if request.Method == http.MethodConnect {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body []byte
		var contentType string
		switch request.URL.Path {
		case "/":
			body = []byte(preamblePage)
			contentType = "text/html"
		case "/style.css":
			body = []byte("body{font-family:sans-serif}")
			contentType = "text/css"
		case "/app.js":
			body = []byte("console.log('site')")
			contentType = "application/javascript"
		case "/img/logo.png":
			body = []byte("not-a-real-png")
			contentType = "image/png"
		default:
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", contentType)
		if encoding != "" && encoding != "identity" {
			body = compress(body)
			writer.Header().Set("Content-Encoding", encoding)
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{
		Handler:   handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
	}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	site.address = listener.Addr().String()
	return site
}

func TestNaivePreambleFrontingSite(t *testing.T) {
	for _, encoding := range []string{"zstd", "br", "gzip", "deflate", "identity"} {
		t.Run(encoding, func(t *testing.T) {
			env := setupTestEnvWithoutServer(t)
			site := startFrontingSite(t, env, encoding)
			_, portString, err := net.SplitHostPort(site.address)
			require.NoError(t, err)
			parsed, err := strconv.Atoi(portString)
			require.NoError(t, err)

			client := env.newNaiveClient(t, cronet.NaiveClientOptions{
				ServerAddress: M.ParseSocksaddrHostPort("127.0.0.1", uint16(parsed)),
				ServerName:    "example.org",
			})

			// DialEarly sends the preamble first and then the CONNECT, which this
			// site rejects; only the preamble matters here.
			dialCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			conn, _ := client.DialEarly(dialCtx, M.ParseSocksaddrHostPort("127.0.0.1", 9))
			cancel()
			if conn != nil {
				_ = conn.Close()
			}

			require.Eventually(t, func() bool {
				paths := site.paths()
				return containsAll(paths, "GET /", "GET /style.css", "GET /app.js", "HEAD /img/logo.png")
			}, 10*time.Second, 50*time.Millisecond, "discovered subresources were not requested: %v", site.paths())

			paths := site.paths()
			require.NotContains(t, paths, "GET /about.html")
			require.NotContains(t, paths, "GET /x.css")

			for _, request := range site.requests() {
				require.Empty(t, request.headers["padding"], "preamble %s must not send padding", request.path)
				require.Empty(t, request.headers["proxy-authorization"], "preamble %s must not send credentials", request.path)
				if request.method == http.MethodConnect {
					continue
				}
				require.Contains(t, request.headers["user-agent"], "Chrome/",
					"preamble %s must send a browser user agent", request.path)
			}
			root := site.requests()[0]
			require.Equal(t, "GET", root.method)
			require.Equal(t, "/", root.path)
		})
	}
}

func TestNaivePreambleDisabled(t *testing.T) {
	env := setupTestEnv(t)
	client := env.newNaiveClient(t, cronet.NaiveClientOptions{
		DisablePreamble: true,
	})
	netLogPath := startNetLogForTest(t, client, "preamble-disabled.json", true)

	echoPort := reserveTCPPort(t)
	startEchoServer(t, echoPort)

	dialCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := client.DialContext(dialCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	require.NoError(t, err)
	defer conn.Close()
	payload := []byte("no-preamble")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	response := make([]byte, len(payload))
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	require.Equal(t, payload, response)

	stopAndWaitNetLog(t, client)
	streams := parseNetLogStreams(t, netLogPath)
	require.Len(t, streams, 1, "only the CONNECT should be sent: %v", streams)
	require.Equal(t, "CONNECT", streams[0].method)
}

func containsAll(values []string, wanted ...string) bool {
	for _, want := range wanted {
		found := false
		for _, value := range values {
			if value == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// --- T8c: the root page is parsed while it is still arriving ---------------

// A link from the first chunk must be requested before the rest of the page is
// sent, as the native client does.
func TestNaivePreambleStreaming(t *testing.T) {
	env := setupTestEnvWithoutServer(t)
	certificate, err := tls.LoadX509KeyPair(env.certPath, env.keyPath)
	require.NoError(t, err)

	const (
		firstChunk  = `<!doctype html><html><head><link rel="stylesheet" href="/early.css"></head><body>`
		secondChunk = `<script src="/late.js"></script></body></html>`
	)
	var mutex sync.Mutex
	var earlyRequested, secondChunkSent time.Time

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(firstChunk))
			writer.(http.Flusher).Flush()
			time.Sleep(500 * time.Millisecond)
			mutex.Lock()
			secondChunkSent = time.Now()
			mutex.Unlock()
			_, _ = writer.Write([]byte(secondChunk))
			writer.(http.Flusher).Flush()
		case "/early.css":
			mutex.Lock()
			earlyRequested = time.Now()
			mutex.Unlock()
			_, _ = writer.Write([]byte("body{}"))
		case "/late.js":
			_, _ = writer.Write([]byte("1"))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	_, portString, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portString)
	require.NoError(t, err)

	client := env.newNaiveClient(t, cronet.NaiveClientOptions{
		ServerAddress: M.ParseSocksaddrHostPort("127.0.0.1", uint16(port)),
		ServerName:    "example.org",
	})
	dialCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	conn, _ := client.DialEarly(dialCtx, M.ParseSocksaddrHostPort("127.0.0.1", 9))
	cancel()
	if conn != nil {
		_ = conn.Close()
	}

	require.Eventually(t, func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return !earlyRequested.IsZero() && !secondChunkSent.IsZero()
	}, 10*time.Second, 20*time.Millisecond, "both chunks and the early request are expected")

	mutex.Lock()
	defer mutex.Unlock()
	require.Less(t, earlyRequested, secondChunkSent,
		"a link from the first chunk must be requested before the rest of the page is written")
}

// --- T8b: end to end against the naive Caddy fork -------------------------

// caddyBinaryPath returns the klzgrad Caddy build if available; the test is
// skipped otherwise.
func caddyBinaryPath(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("CRONET_TEST_CADDY"); configured != "" {
		if info, err := os.Stat(configured); err == nil && !info.IsDir() {
			return configured
		}
	}
	for _, name := range []string{"caddy.exe", "caddy"} {
		if binary, err := exec.LookPath(name); err == nil {
			return binary
		}
	}
	return ""
}

func TestNaivePreambleCaddy(t *testing.T) {
	caddyBinary := caddyBinaryPath(t)
	if caddyBinary == "" {
		t.Skip("klzgrad Caddy binary not found (set CRONET_TEST_CADDY)")
	}
	env := setupTestEnvWithoutServer(t)
	certPath, keyPath := env.certPath, env.keyPath

	root := t.TempDir()
	siteDir := filepath.Join(root, "site")
	imgDir := filepath.Join(siteDir, "img")
	require.NoError(t, os.MkdirAll(imgDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(siteDir, "index.html"), []byte(preamblePage+strings.Repeat("<!-- pad -->", 64)), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(siteDir, "style.css"), []byte("body{font-family:sans-serif}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(siteDir, "app.js"), []byte("console.log('site')"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(imgDir, "logo.png"), []byte("not-a-real-png"), 0o644))

	port := reserveTCPPort(t)
	accessLogPath := filepath.ToSlash(filepath.Join(artifactDir(t, "trace"), "caddy-access.log"))
	serverLogPath := filepath.ToSlash(filepath.Join(artifactDir(t, "trace"), "caddy.log"))
	caddyfile := fmt.Sprintf(`{
	order forward_proxy before file_server
	auto_https off
	admin off
	servers {
		protocols h1 h2
	}
	log {
		output file %s
		level INFO
	}
}

:%d {
	bind 127.0.0.1
	tls %s %s
	encode
	log {
		output file %s
		format json
	}
	forward_proxy {
		basic_auth test test
		hide_ip
		hide_via
		probe_resistance
		acl {
			allow 127.0.0.1/32
		}
	}
	file_server {
		root %s
	}
}
`, serverLogPath, port, filepath.ToSlash(certPath), filepath.ToSlash(keyPath), accessLogPath, filepath.ToSlash(siteDir))
	caddyfilePath := filepath.Join(root, "Caddyfile")
	require.NoError(t, os.WriteFile(caddyfilePath, []byte(caddyfile), 0o644))

	command := startCaddy(t, caddyBinary, caddyfilePath, port)
	_ = command
	client := env.newNaiveClient(t, cronet.NaiveClientOptions{
		ServerAddress: M.ParseSocksaddrHostPort("127.0.0.1", port),
		ServerName:    "example.org",
	})
	netLogPath := startNetLogForTest(t, client, "preamble-caddy.json", true)

	echoPort := reserveTCPPort(t)
	startEchoServer(t, echoPort)

	dialCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	conn, err := client.DialContext(dialCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	require.NoError(t, err)
	defer conn.Close()
	payload := []byte("caddy-end-to-end")
	_, err = conn.Write(payload)
	require.NoError(t, err)
	response := make([]byte, len(payload))
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	require.Equal(t, payload, response)

	stopAndWaitNetLog(t, client)
	streams := parseNetLogStreams(t, netLogPath)
	rootIndex := findStream(streams, "GET", "/")
	require.GreaterOrEqual(t, rootIndex, 0, "no preamble root request found: %v", streams)
	connectIndex := findStream(streams, "CONNECT", "")
	require.GreaterOrEqual(t, connectIndex, 0)
	require.Equal(t, streams[rootIndex].session, streams[connectIndex].session,
		"preamble and CONNECT must share one session")
	// As in the native client, the whole preamble is sent before the CONNECT.
	for _, path := range []string{"/style.css", "/app.js", "/img/logo.png"} {
		index := findStreamByPath(streams, path)
		require.GreaterOrEqual(t, index, 0, "preamble did not request %s: %v", path, streams)
		require.Equal(t, streams[rootIndex].session, streams[index].session,
			"%s must share the session with the root request", path)
		require.Less(t, index, connectIndex, "%s must be sent before the CONNECT", path)
	}
}

func startCaddy(t *testing.T, binary string, caddyfilePath string, port uint16) *os.Process {
	t.Helper()
	command := exec.Command(binary, "run", "--config", caddyfilePath)
	traceFile, tracePath := createArtifactTempFile(t, "trace", "caddy-*.log")
	command.Stdout = traceFile
	command.Stderr = traceFile
	require.NoError(t, command.Start(), "failed to start caddy; trace: %s", tracePath)
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = traceFile.Close()
	})

	waitForServerReady(t, "tcp", port, 20*time.Second, tracePath)
	return command.Process
}
