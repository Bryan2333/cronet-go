package cronet

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Expectations are byte-for-byte identical to the original C++ tag scanner.
func TestExtractPreambleLinks(t *testing.T) {
	testCases := []struct {
		html string
		want string
	}{
		{`<link rel="stylesheet" href="/a.css">`, `["/a.css"]`},
		{`<script src="/a.js" defer></script>`, `["/a.js"]`},
		{`<IMG SRC=/logo.png>`, `["/logo.png"]`},
		{`<img src>`, `[]`},
		{`<img src="">`, `[""]`},                                 // an empty value is returned as such
		{`<linkage href="/x.css">`, `["/x.css"]`},                // prefix-only tag match
		{`<scriptfoo src="/y.js">`, `["/y.js"]`},                 // prefix-only tag match
		{`</link>`, `[]`},                                        // closing tags do not match
		{`<a href="/about.html">x</a>`, `[]`},                    // only link/script/img
		{`<!-- <link href="/fake.css"> -->`, `[]`},               // comments are skipped
		{`<img src="/a>b.png">`, `["/a"]`},                       // value truncated at '>'
		{`<link href="/a.css" src="/ignored.js">`, `["/a.css"]`}, // link only takes href
		{`<link  href = '/spaced.css' >`, `["/spaced.css"]`},     //
		{`<img data-src="/lazy.png">`, `[]`},                     // only src
		{`<link href="/a.css"><script src="/b.js"></script>`, `["/a.css" "/b.js"]`},
	}
	for _, testCase := range testCases {
		got := extractPreambleLinks(testCase.html)
		if formatList(got) != testCase.want {
			t.Errorf("extractPreambleLinks(%q) = %s, want %s", testCase.html, formatList(got), testCase.want)
		}
	}
}

// formatList quotes every value, so an empty value cannot be mistaken for an
// absent one.
func formatList(values []string) string {
	return fmt.Sprintf("%q", values)
}

// Expectations come from compiling the original C++ brand list generator.
func TestBrandMajorVersionList(t *testing.T) {
	testCases := map[int]string{
		150: `"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"`,
		153: `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"`,
		154: `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`,
		155: `"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"`,
	}
	for major, want := range testCases {
		if got := brandMajorVersionList(major); got != want {
			t.Errorf("brandMajorVersionList(%d) = %q, want %q", major, got, want)
		}
	}
}

func TestNewClientHints(t *testing.T) {
	testCases := []struct {
		goos       string
		platform   string
		expectInUA string
	}{
		{"windows", `"Windows"`, "Windows NT 10.0; Win64; x64"},
		{"darwin", `"macOS"`, "Macintosh; Intel Mac OS X 10_15_7"},
		{"linux", `"Linux"`, "X11; Linux x86_64"},
		{"android", `"Android"`, "Linux; Android 10; K"},
		{"ios", `"iOS"`, "iPhone; CPU iPhone OS 14_0 like Mac OS X"},
	}
	for _, testCase := range testCases {
		hints := newClientHints(154, testCase.goos)
		wantUA := "Mozilla/5.0 (" + testCase.expectInUA + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
		if hints.userAgent != wantUA {
			t.Errorf("goos %s: user agent = %q, want %q", testCase.goos, hints.userAgent, wantUA)
		}
		if hints.platform != testCase.platform {
			t.Errorf("goos %s: platform = %q, want %q", testCase.goos, hints.platform, testCase.platform)
		}
		if hints.mobile != "?0" {
			t.Errorf("goos %s: mobile = %q, want ?0", testCase.goos, hints.mobile)
		}
	}
}

func TestChromiumMajor(t *testing.T) {
	if major := chromiumMajor("154.0.8037.49"); major != 154 {
		t.Errorf("chromiumMajor(154.0.8037.49) = %d, want 154", major)
	}
	if major := chromiumMajor("150"); major != 150 {
		t.Errorf("chromiumMajor(150) = %d, want 150", major)
	}
	if major := chromiumMajor(""); major != fallbackChromiumMajor {
		t.Errorf("chromiumMajor(\"\") = %d, want %d", major, fallbackChromiumMajor)
	}
}

func TestPreambleReader(t *testing.T) {
	plain := []byte("<link href=\"/a.css\"><script src=\"/b.js\">" + strings.Repeat(" padding", 100))

	encodeGzip := func(data []byte) []byte {
		buffer := &bytes.Buffer{}
		writer := gzip.NewWriter(buffer)
		_, _ = writer.Write(data)
		_ = writer.Close()
		return buffer.Bytes()
	}
	encodeZlib := func(data []byte) []byte {
		buffer := &bytes.Buffer{}
		writer := zlib.NewWriter(buffer)
		_, _ = writer.Write(data)
		_ = writer.Close()
		return buffer.Bytes()
	}
	encodeFlate := func(data []byte) []byte {
		buffer := &bytes.Buffer{}
		writer, _ := flate.NewWriter(buffer, flate.DefaultCompression)
		_, _ = writer.Write(data)
		_ = writer.Close()
		return buffer.Bytes()
	}
	encodeBrotli := func(data []byte) []byte {
		buffer := &bytes.Buffer{}
		writer := brotli.NewWriter(buffer)
		_, _ = writer.Write(data)
		_ = writer.Close()
		return buffer.Bytes()
	}
	encodeZstd := func(data []byte) []byte {
		writer, _ := zstd.NewWriter(nil)
		return writer.EncodeAll(data, nil)
	}

	testCases := []struct {
		name            string
		contentEncoding string
		body            []byte
		want            []byte
		passthrough     bool
	}{
		{"identity header", "", plain, plain, true},
		{"identity encoding", "identity", plain, plain, true},
		{"unknown encoding", "snappy", plain, plain, true},
		{"gzip", "gzip", encodeGzip(plain), plain, false},
		{"x-gzip", "x-gzip", encodeGzip(plain), plain, false},
		{"zlib deflate", "deflate", encodeZlib(plain), plain, false},
		{"raw deflate", "deflate", encodeFlate(plain), plain, false},
		{"brotli", "br", encodeBrotli(plain), plain, false},
		{"zstd", "zstd", encodeZstd(plain), plain, false},
		{"uppercase", "GZip", encodeGzip(plain), plain, false},
		{"layered", "gzip, br", encodeBrotli(encodeGzip(plain)), plain, false},
	}
	for _, testCase := range testCases {
		reader, decoded := preambleReader(testCase.contentEncoding, bytes.NewReader(testCase.body))
		if testCase.passthrough {
			if decoded {
				t.Errorf("%s: must be passed through raw", testCase.name)
			}
			continue
		}
		if !decoded {
			t.Errorf("%s: must be decoded", testCase.name)
			continue
		}
		got, err := io.ReadAll(reader)
		if err != nil {
			t.Errorf("%s: unexpected error %v", testCase.name, err)
			continue
		}
		if !bytes.Equal(got, testCase.want) {
			t.Errorf("%s: decoded %d bytes, want %d bytes", testCase.name, len(got), len(testCase.want))
		}
		// Decoders have to work on partial reads, as the response arrives in
		// arbitrarily sized chunks.
		chunked, chunkedDecoded := preambleReader(testCase.contentEncoding, &dripReader{data: testCase.body, chunk: 3})
		if !chunkedDecoded {
			t.Errorf("%s: chunked decoding disabled", testCase.name)
			continue
		}
		got, err = io.ReadAll(chunked)
		if err != nil {
			t.Errorf("%s: chunked read error %v", testCase.name, err)
			continue
		}
		if !bytes.Equal(got, testCase.want) {
			t.Errorf("%s: chunked decoded %d bytes, want %d", testCase.name, len(got), len(testCase.want))
		}
	}

	// Oversized bodies are truncated instead of being decoded without bound.
	big := bytes.Repeat([]byte("a"), preambleMaxBodySize*2)
	reader, decoded := preambleReader("zstd", bytes.NewReader(encodeZstd(big)))
	if !decoded {
		t.Fatal("oversized: zstd must be decoded")
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("oversized: unexpected error %v", err)
	}
	if len(got) != preambleMaxBodySize {
		t.Errorf("oversized: decoded %d bytes, want %d", len(got), preambleMaxBodySize)
	}
}

// dripReader returns the data in small chunks, to exercise streaming decoders.
type dripReader struct {
	data  []byte
	chunk int
}

func (r *dripReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(r.chunk, len(p), len(r.data))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func testPreambleState(t *testing.T, quic bool) *preambleState {
	t.Helper()
	client := &NaiveClient{
		serverURL:     "https://example.org:443",
		rootReferer:   "https://example.org/",
		quicEnabled:   quic,
		tunnelTimeout: 30 * time.Minute,
		hints:         newClientHints(154, "windows"),
	}
	return newPreambleState(client, StreamEngine{}, 0)
}

func headerNames(headers []HeaderField) []string {
	names := make([]string, 0, len(headers))
	for _, header := range headers {
		names = append(names, header.Name)
	}
	return names
}

func headerValue(headers []HeaderField, name string) string {
	for _, header := range headers {
		if header.Name == name {
			return header.Value
		}
	}
	return ""
}

// The wire order has to match PreambleGetter::AddRootHeaders()/AddHeaders().
func TestPreambleHeaderOrder(t *testing.T) {
	state := testPreambleState(t, false)
	testCases := []struct {
		request preambleRequest
		want    string
	}{
		{preambleRequest{path: "/"}, "sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform upgrade-insecure-requests user-agent accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest accept-encoding accept-language priority -network-isolation-key"},
		{preambleRequest{path: "/a.css", ext: "css"}, "sec-ch-ua-platform user-agent sec-ch-ua sec-ch-ua-mobile accept sec-fetch-site sec-fetch-mode sec-fetch-dest referer accept-encoding accept-language priority -network-isolation-key"},
		{preambleRequest{path: "/a.js", ext: "js"}, "sec-ch-ua-platform user-agent sec-ch-ua sec-ch-ua-mobile accept sec-fetch-site sec-fetch-mode sec-fetch-dest referer accept-encoding accept-language priority -network-isolation-key"},
		{preambleRequest{path: "/a.png", ext: "png"}, "sec-ch-ua-platform user-agent sec-ch-ua sec-ch-ua-mobile accept sec-fetch-site sec-fetch-mode sec-fetch-dest referer accept-encoding accept-language priority -network-isolation-key"},
	}
	for _, testCase := range testCases {
		got := strings.Join(headerNames(state.headers(testCase.request, 0)), " ")
		if got != testCase.want {
			t.Errorf("header order for %q = %q, want %q", testCase.request.path, got, testCase.want)
		}
	}

	quicState := testPreambleState(t, true)
	got := strings.Join(headerNames(quicState.headers(preambleRequest{path: "/"}, 0)), " ")
	want := "sec-ch-ua sec-ch-ua-mobile sec-ch-ua-platform upgrade-insecure-requests user-agent accept sec-fetch-site sec-fetch-mode sec-fetch-user sec-fetch-dest accept-encoding accept-language priority -force-quic -network-isolation-key"
	if got != want {
		t.Errorf("quic header order = %q, want %q", got, want)
	}
}

func TestPreambleHeaders(t *testing.T) {
	state := testPreambleState(t, false)
	epoch := uint64(3)

	root := state.headers(preambleRequest{path: "/"}, epoch)
	wantRoot := map[string]string{
		"sec-ch-ua":                 `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`,
		"sec-ch-ua-mobile":          "?0",
		"sec-ch-ua-platform":        `"Windows"`,
		"upgrade-insecure-requests": "1",
		"user-agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
		"accept":                    preambleAcceptHTML,
		"sec-fetch-site":            "none",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-user":            "?1",
		"sec-fetch-dest":            "document",
		"accept-encoding":           "gzip, deflate, br, zstd",
		"accept-language":           "en-US,en;q=0.9",
		"priority":                  "u=0, i",
		"-network-isolation-key":    "https://naive-0-3:443",
	}
	for name, want := range wantRoot {
		if got := headerValue(root, name); got != want {
			t.Errorf("root header %s = %q, want %q", name, got, want)
		}
	}
	if len(root) != len(wantRoot) {
		t.Errorf("root has %d headers, want %d: %v", len(root), len(wantRoot), headerNames(root))
	}

	// Subresources must not carry credentials, padding or user extra headers.
	for _, ext := range []string{"css", "js", "png"} {
		headers := state.headers(preambleRequest{path: "/a." + ext, ext: ext}, epoch)
		for _, forbidden := range []string{"padding", "padding-type-request", "proxy-authorization", "fastopen", "-connect-authority"} {
			if headerValue(headers, forbidden) != "" {
				t.Errorf("subresource %s must not send %s", ext, forbidden)
			}
		}
		if got := headerValue(headers, "referer"); got != "https://example.org/" {
			t.Errorf("subresource %s referer = %q", ext, got)
		}
		if got := headerValue(headers, "sec-fetch-site"); got != "same-origin" || headerValue(headers, "sec-fetch-mode") != "no-cors" {
			t.Errorf("subresource %s has wrong sec-fetch headers", ext)
		}
	}

	css := state.headers(preambleRequest{path: "/a.css", ext: "css"}, epoch)
	if headerValue(css, "accept") != "text/css,*/*;q=0.1" || headerValue(css, "sec-fetch-dest") != "style" || headerValue(css, "priority") != "u=0" {
		t.Errorf("css headers = %v", css)
	}
	js := state.headers(preambleRequest{path: "/a.js", ext: "js"}, epoch)
	if headerValue(js, "accept") != "*/*" || headerValue(js, "sec-fetch-dest") != "script" || headerValue(js, "priority") != "u=2" {
		t.Errorf("js headers = %v", js)
	}
	image := state.headers(preambleRequest{path: "/a.png", ext: "png"}, epoch)
	if headerValue(image, "sec-fetch-dest") != "image" || headerValue(image, "priority") != "i" {
		t.Errorf("image headers = %v", image)
	}

	if got := headerValue(root, "-force-quic"); got != "" {
		t.Errorf("non-quic preamble must not send -force-quic, got %q", got)
	}
}

func TestPreambleMethod(t *testing.T) {
	testCases := []struct {
		ext  string
		want string
	}{
		{"css", "GET"},
		{"js", "GET"},
		{"png", "HEAD"},
		{"jpg", "HEAD"},
		{"jxl", "HEAD"},
	}
	for _, testCase := range testCases {
		if got := preambleMethod(preambleRequest{ext: testCase.ext}); got != testCase.want {
			t.Errorf("preambleMethod(%q) = %q, want %q", testCase.ext, got, testCase.want)
		}
	}
}

func TestPreamblePriorities(t *testing.T) {
	testCases := map[string]int{
		"/":             5,
		"/a.css":        5,
		"/a.js":         3,
		"/a.png":        2,
		"/a.css?v=1":    2, // naive compares the whole path including the query
		"/deep/a.css":   5,
		"/img/logo.png": 2,
	}
	for path, want := range testCases {
		if got := preamblePriority(path); got != want {
			t.Errorf("preamblePriority(%q) = %d, want %d", path, got, want)
		}
	}
}

func TestPreambleStateAttempts(t *testing.T) {
	state := testPreambleState(t, false)
	state.client.tunnelTimeout = 30 * time.Minute
	now := time.Now()

	mode, epoch, wait := state.beginAttempt(now)
	if mode != preambleModeFull || epoch != 0 || wait != nil {
		t.Fatalf("first attempt = (%v, %d, %v), want full/0/nil", mode, epoch, wait)
	}
	if state.epoch != 0 || !state.attempted || !state.running {
		t.Fatalf("state after first attempt = %+v", state)
	}
	if !state.deadline.After(now) {
		t.Error("deadline was not set")
	}

	// A concurrent connection has to wait for the running preamble.
	mode, _, wait = state.beginAttempt(time.Now())
	if mode != preambleModeWait || wait == nil {
		t.Fatalf("concurrent attempt = (%v, %v), want wait", mode, wait)
	}

	state.finishAttempt()
	if state.running {
		t.Error("state still running after finishAttempt")
	}
	state.mutex.Lock()
	select {
	case <-wait:
	default:
		t.Error("wait channel was not closed")
	}
	state.requests = []preambleRequest{{path: "/"}, {path: "/a.css", ext: "css"}}
	state.mutex.Unlock()

	// While the session is alive only one random request is sent.
	mode, epoch, _ = state.beginAttempt(time.Now())
	if mode != preambleModeOne || epoch != 0 {
		t.Fatalf("live session attempt = (%v, %d), want one/0", mode, epoch)
	}

	// An idle session is treated as gone: full preamble, same epoch.
	state.mutex.Lock()
	state.lastActivity = time.Now().Add(-time.Hour)
	state.mutex.Unlock()
	mode, epoch, _ = state.beginAttempt(time.Now())
	if mode != preambleModeFull || epoch != 0 {
		t.Fatalf("idle attempt = (%v, %d), want full/0", mode, epoch)
	}
	state.finishAttempt()

	// Rotating bumps the epoch and resets the discovered requests.
	state.mutex.Lock()
	state.deadline = time.Now().Add(-time.Minute)
	state.mutex.Unlock()
	mode, epoch, _ = state.beginAttempt(time.Now())
	if mode != preambleModeFull || epoch != 1 {
		t.Fatalf("rotation attempt = (%v, %d), want full/1", mode, epoch)
	}
	state.mutex.Lock()
	if len(state.requests) != 1 || state.requests[0].path != "/" {
		t.Errorf("requests were not reset on rotation: %v", state.requests)
	}
	// A running preamble is waited for even after the deadline; replacing it
	// would overwrite the runningDone channel other connections wait on.
	state.deadline = time.Now().Add(-time.Second)
	state.mutex.Unlock()
	mode, waitingEpoch, wait := state.beginAttempt(time.Now())
	if mode != preambleModeWait || waitingEpoch != 1 || wait == nil {
		t.Fatalf("expired while running = (%v, %d, %v), want wait/1", mode, waitingEpoch, wait)
	}
	state.mutex.Lock()
	if state.epoch != 1 {
		t.Errorf("epoch was bumped while a preamble was running: %d", state.epoch)
	}
	state.mutex.Unlock()
	state.finishAttempt()
	if key := state.isolationKey(1); key != "https://naive-0-1:443" {
		t.Errorf("isolationKey = %q", key)
	}

	// QUIC sessions die much faster, so the idle grace differs.
	quicState := testPreambleState(t, true)
	if grace := quicState.idleGrace(); grace != preambleQUICIdleGrace {
		t.Errorf("quic idle grace = %v", grace)
	}
	if grace := state.idleGrace(); grace != preambleTCPIdleGrace {
		t.Errorf("tcp idle grace = %v", grace)
	}
}

func TestPathExtension(t *testing.T) {
	testCases := map[string]string{
		"/a.css":         "css",
		"/a.b.js":        "js",
		"/dir/a.png":     "png",
		"/a":             "",
		"/":              "",
		"/dir/":          "",
		"/a.CSS":         "CSS", // naive compares extensions case sensitively
		"/img/logo.jpeg": "jpeg",
	}
	for path, want := range testCases {
		if got := pathExtension(path); got != want {
			t.Errorf("pathExtension(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestEffectivePort(t *testing.T) {
	testCases := []struct {
		raw  string
		want string
	}{
		{"https://example.org/a", "443"},
		{"https://example.org:8443/a", "8443"},
		{"http://example.org/a", "80"},
		{"http://example.org:8080/a", "8080"},
	}
	for _, testCase := range testCases {
		parsed, err := url.Parse(testCase.raw)
		if err != nil {
			t.Fatalf("parse %s: %v", testCase.raw, err)
		}
		if got := effectivePort(parsed); got != testCase.want {
			t.Errorf("effectivePort(%s) = %q, want %q", testCase.raw, got, testCase.want)
		}
	}
}

func TestFilterPreambleLink(t *testing.T) {
	root, err := url.Parse("https://example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	testCases := []struct {
		name  string
		known []string
		link  string
		want  string
	}{
		{"stylesheet", nil, "/style.css", "/style.css|css"},
		{"script", nil, "/app.js", "/app.js|js"},
		{"image", nil, "/img/logo.png", "/img/logo.png|png"},
		{"absolute same host", nil, "https://example.org/a.css", "/a.css|css"},
		{"query is kept", nil, "/style.css?v=1", "/style.css?v=1|css"},
		{"extension ignores query", nil, "/deep/font.woff2?v=2", ""},
		{"relative path", nil, "img/a.gif", "/img/a.gif|gif"},
		{"already known", []string{"/style.css"}, "/style.css", ""},
		{"root is not a subresource", nil, "/", ""},
		{"not whitelisted", nil, "/about.html", ""},
		{"other host", nil, "https://other.example.org/x.css", ""},
		{"other port", nil, "https://example.org:8443/x.css", ""},
		{"not http", nil, "mailto:a@example.org", ""},
	}
	for _, testCase := range testCases {
		known := make(map[string]bool, len(testCase.known)+1)
		known["/"] = true
		for _, path := range testCase.known {
			known[path] = true
		}
		request, ok := filterPreambleLink(root, known, testCase.link)
		got := ""
		if ok {
			got = request.path + "|" + request.ext
		}
		if got != testCase.want {
			t.Errorf("%s: filterPreambleLink(%q) = %q, want %q", testCase.name, testCase.link, got, testCase.want)
		}
	}
}
