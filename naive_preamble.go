package cronet

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"io"
	"math/rand"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Preamble traffic: before the first tunnel request of a session, and after
// each tunnel rotation, send browser requests to the fronting website so that
// the start of the connection looks like a page load. Mirrors naiveproxy's
// preamble_getter.cc and naive_proxy.cc.

const (
	// QUIC sessions are gone 30s after the last activity (the negotiated
	// max_idle_timeout), so a new one has to start over with the root page.
	preambleQUICIdleGrace = 20 * time.Second
	// Measured floor for HTTP/2 sessions; they survived 600s idle.
	preambleTCPIdleGrace = 10 * time.Minute

	preambleMaxBodySize = 1 << 20
	// naive reads the root page in 64 KiB chunks (kBufferSize).
	preambleReadSize = 64 * 1024
	// Used only if the engine version cannot be parsed.
	fallbackChromiumMajor = 154
)

var (
	preambleAcceptHTML        = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	preambleAllowedExtensions = map[string]bool{
		"css": true, "js": true, "png": true, "gif": true, "jpg": true, "jpeg": true,
		"webp": true, "bmp": true, "avif": true, "jxl": true,
	}
)

type preambleRequest struct {
	// PathForRequestPiece(): path with query, without fragment.
	path string
	ext  string
}

func preamblePriority(path string) int {
	if path == "/" || strings.HasSuffix(path, ".css") {
		return 5 // net::HIGHEST
	}
	if strings.HasSuffix(path, ".js") {
		return 3 // net::LOW
	}
	return 2 // net::LOWEST
}

type preambleMode int

// beginAttempt outcomes.
const (
	// Run the whole preamble in the calling goroutine.
	preambleModeFull preambleMode = iota
	preambleModeWait
	preambleModeOne
)

// Per tunnel slot, matching naive's Tunnel.
type preambleState struct {
	client       *NaiveClient
	streamEngine StreamEngine
	slot         int

	mutex        sync.Mutex
	requests     []preambleRequest
	deadline     time.Time
	attempted    bool
	running      bool
	runningDone  chan struct{}
	lastActivity time.Time
	epoch        uint64
}

func newPreambleState(client *NaiveClient, streamEngine StreamEngine, slot int) *preambleState {
	return &preambleState{
		client:       client,
		streamEngine: streamEngine,
		slot:         slot,
		requests:     []preambleRequest{{path: "/"}},
		lastActivity: time.Now(),
	}
}

func (s *preambleState) isolationKey(epoch uint64) string {
	return F.ToString("https://naive-", s.slot, "-", epoch, ":443")
}

func (s *preambleState) idleGrace() time.Duration {
	if s.client.quicEnabled {
		return preambleQUICIdleGrace
	}
	if preambleTCPIdleGrace > s.client.tunnelTimeout {
		return s.client.tunnelTimeout
	}
	return preambleTCPIdleGrace
}

// Mirrors NaiveProxy::DoAcceptComplete().
func (s *preambleState) beginAttempt(now time.Time) (preambleMode, uint64, chan struct{}) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// A running preamble makes later connections of this slot wait, as naive's
	// serialized accept state machine does.
	if s.running {
		return preambleModeWait, s.epoch, s.runningDone
	}
	if !s.attempted || now.After(s.deadline) {
		// naive records the deadline before running the preamble, so even a
		// failed preamble uses up this epoch.
		if s.attempted {
			s.epoch++
			s.requests = s.requests[:1]
		}
		s.attempted = true
		s.deadline = now.Add(s.client.tunnelTimeout)
		s.running = true
		s.runningDone = make(chan struct{})
		return preambleModeFull, s.epoch, nil
	}
	if now.Sub(s.lastActivity) > s.idleGrace() {
		// The session is probably gone, which naive would detect through its
		// session pool query. The epoch stays the same.
		s.running = true
		s.runningDone = make(chan struct{})
		return preambleModeFull, s.epoch, nil
	}
	return preambleModeOne, s.epoch, nil
}

func (s *preambleState) finishAttempt() {
	s.mutex.Lock()
	s.running = false
	if s.runningDone != nil {
		close(s.runningDone)
		s.runningDone = nil
	}
	s.lastActivity = time.Now()
	s.mutex.Unlock()
}

func (s *preambleState) noteActivity() {
	s.mutex.Lock()
	s.lastActivity = time.Now()
	s.mutex.Unlock()
}

func (s *preambleState) addDiscovered(html string, epoch uint64) {
	root, err := url.Parse(s.client.serverURL)
	if err != nil {
		return
	}
	s.mutex.Lock()
	known := make(map[string]bool, len(s.requests))
	for _, request := range s.requests {
		known[request.path] = true
	}
	var discovered []preambleRequest
	for _, link := range extractPreambleLinks(html) {
		request, ok := filterPreambleLink(root, known, link)
		if !ok {
			continue
		}
		known[request.path] = true
		discovered = append(discovered, request)
	}
	s.requests = append(s.requests, discovered...)
	s.mutex.Unlock()

	// naive starts the discovered requests while reading the root page, so they
	// are always queued before the CONNECT of this connection; Start is
	// asynchronous, only the reading runs in the background.
	for _, request := range discovered {
		conn, ctx, cancel := s.start(request, epoch)
		if conn == nil {
			continue
		}
		s.client.proxyWaitGroup.Add(1)
		go func() {
			defer s.client.proxyWaitGroup.Done()
			s.drain(conn, ctx, cancel)
		}()
	}
}

// filterPreambleLink resolves one link of a root page the way
// PreambleGetter::DoReadComplete() does.
func filterPreambleLink(root *url.URL, known map[string]bool, link string) (preambleRequest, bool) {
	target, err := root.Parse(link)
	if err != nil {
		return preambleRequest{}, false
	}
	if !strings.EqualFold(target.Hostname(), root.Hostname()) ||
		effectivePort(target) != effectivePort(root) {
		return preambleRequest{}, false
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	if known[path] {
		return preambleRequest{}, false
	}
	ext := pathExtension(target.Path)
	if !preambleAllowedExtensions[ext] {
		return preambleRequest{}, false
	}
	return preambleRequest{path: path, ext: ext}, true
}

func (s *preambleState) randomRequest() (preambleRequest, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if len(s.requests) == 0 {
		return preambleRequest{}, false
	}
	return s.requests[rand.Intn(len(s.requests))], true
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

func pathExtension(path string) string {
	name := path
	if index := strings.LastIndexByte(name, '/'); index >= 0 {
		name = name[index+1:]
	}
	if index := strings.LastIndexByte(name, '.'); index >= 0 {
		return name[index+1:]
	}
	return ""
}

// Same order as PreambleGetter::AddRootHeaders()/AddHeaders().
func (s *preambleState) headers(request preambleRequest, epoch uint64) []HeaderField {
	hints := s.client.hints
	var headers []HeaderField
	if request.ext == "" {
		headers = []HeaderField{
			{"sec-ch-ua", hints.secCHUA},
			{"sec-ch-ua-mobile", hints.mobile},
			{"sec-ch-ua-platform", hints.platform},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", hints.userAgent},
			{"accept", preambleAcceptHTML},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		}
	} else {
		headers = []HeaderField{
			{"sec-ch-ua-platform", hints.platform},
			{"user-agent", hints.userAgent},
			{"sec-ch-ua", hints.secCHUA},
			{"sec-ch-ua-mobile", hints.mobile},
		}
		switch request.ext {
		case "css":
			headers = append(headers,
				HeaderField{"accept", "text/css,*/*;q=0.1"},
				HeaderField{"sec-fetch-site", "same-origin"},
				HeaderField{"sec-fetch-mode", "no-cors"},
				HeaderField{"sec-fetch-dest", "style"},
				HeaderField{"referer", s.client.rootReferer},
				HeaderField{"accept-encoding", "gzip, deflate, br, zstd"},
				HeaderField{"accept-language", "en-US,en;q=0.9"},
				HeaderField{"priority", "u=0"})
		case "js":
			headers = append(headers,
				HeaderField{"accept", "*/*"},
				HeaderField{"sec-fetch-site", "same-origin"},
				HeaderField{"sec-fetch-mode", "no-cors"},
				HeaderField{"sec-fetch-dest", "script"},
				HeaderField{"referer", s.client.rootReferer},
				HeaderField{"accept-encoding", "gzip, deflate, br, zstd"},
				HeaderField{"accept-language", "en-US,en;q=0.9"},
				HeaderField{"priority", "u=2"})
		default:
			headers = append(headers,
				HeaderField{"accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"},
				HeaderField{"sec-fetch-site", "same-origin"},
				HeaderField{"sec-fetch-mode", "no-cors"},
				HeaderField{"sec-fetch-dest", "image"},
				HeaderField{"referer", s.client.rootReferer},
				HeaderField{"accept-encoding", "gzip, deflate, br, zstd"},
				HeaderField{"accept-language", "en-US,en;q=0.9"},
				HeaderField{"priority", "i"})
		}
	}
	// Internal headers are consumed by the stream, their position is irrelevant.
	if s.client.quicEnabled {
		headers = append(headers, HeaderField{"-force-quic", "true"})
	}
	return append(headers, HeaderField{"-network-isolation-key", s.isolationKey(epoch)})
}

// start queues a preamble request and returns the connection to drain.
func (s *preambleState) start(request preambleRequest, epoch uint64) (*BidirectionalConn, context.Context, context.CancelFunc) {
	s.client.logger.DebugContext(s.client.ctx, "preamble ", request.path)
	ctx, cancel := context.WithTimeout(s.client.ctx, s.client.preambleTimeout)
	conn := s.streamEngine.CreateConn(ctx, s.client.logger, true, false)
	if err := conn.StartWithHeaders(preambleMethod(request), s.client.serverURL+request.path, s.headers(request, epoch), preamblePriority(request.path), true); err != nil {
		cancel()
		conn.Close()
		return nil, nil, nil
	}
	return conn, ctx, cancel
}

// drain discards the response body, as naive does for subresources.
func (s *preambleState) drain(conn *BidirectionalConn, ctx context.Context, cancel context.CancelFunc) {
	defer cancel()
	if _, err := conn.WaitForHeadersContext(ctx); err != nil {
		conn.Close()
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(conn, preambleMaxBodySize))
	conn.Close()
	s.noteActivity()
}

func (s *preambleState) send(request preambleRequest, epoch uint64) {
	conn, ctx, cancel := s.start(request, epoch)
	if conn == nil {
		return
	}
	s.drain(conn, ctx, cancel)
}

// Stylesheets and scripts use GET, everything else HEAD.
func preambleMethod(request preambleRequest) string {
	if request.ext == "css" || request.ext == "js" {
		return "GET"
	}
	return "HEAD"
}

// Mirrors PreambleGetter::StartOne().
func (s *preambleState) startOne(epoch uint64) {
	request, loaded := s.randomRequest()
	if !loaded {
		return
	}
	s.send(request, epoch)
}

// Mirrors PreambleGetter::Start(): the root page, then its subresources.
func (s *preambleState) runFull(ctx context.Context, epoch uint64) {
	client := s.client
	requestCtx, cancel := context.WithTimeout(ctx, client.preambleTimeout)
	defer cancel()

	root := preambleRequest{path: "/"}
	conn := s.streamEngine.CreateConn(requestCtx, client.logger, true, false)
	if err := conn.StartWithHeaders("GET", client.serverURL, s.headers(root, epoch), preamblePriority(root.path), true); err != nil {
		conn.Close()
		client.logger.WarnContext(client.ctx, "preamble failed: ", err)
		return
	}
	headers, err := conn.WaitForHeadersContext(requestCtx)
	if err != nil {
		conn.Close()
		client.logger.WarnContext(client.ctx, "preamble failed: ", err)
		return
	}
	// naive ignores the response code during preamble.
	client.logger.DebugContext(client.ctx, "preamble ", client.rootReferer, " status: ", headers[":status"])

	var body io.Reader = conn
	body, _ = preambleReader(headers["content-encoding"], conn)

	// naive reads 64 KiB chunks and parses the previous plus the current chunk,
	// so links show up while the page is still arriving.
	buffer := make([]byte, preambleReadSize)
	var lastContent []byte
	var window []byte
	for {
		read, err := body.Read(buffer)
		if read > 0 {
			window = append(window[:0], lastContent...)
			window = append(window, buffer[:read]...)
			s.addDiscovered(string(window), epoch)
			lastContent = append(lastContent[:0], buffer[:read]...)
		}
		if err != nil {
			break
		}
	}
	conn.Close()
	s.noteActivity()
}

// preambleReader wraps the body with the decoders of FilterSourceStream,
// limited to preambleMaxBodySize. ok is false for identity or unknown
// encodings, which are used raw.
func preambleReader(contentEncoding string, body io.Reader) (io.Reader, bool) {
	if contentEncoding == "" {
		return io.LimitReader(body, preambleMaxBodySize), false
	}
	var encodings []string
	for _, encoding := range strings.Split(contentEncoding, ",") {
		switch strings.ToLower(strings.TrimSpace(encoding)) {
		case "gzip", "x-gzip":
			encodings = append(encodings, "gzip")
		case "deflate":
			encodings = append(encodings, "deflate")
		case "br":
			encodings = append(encodings, "br")
		case "zstd":
			encodings = append(encodings, "zstd")
		default:
			return io.LimitReader(body, preambleMaxBodySize), false
		}
	}
	// Layered encodings are decoded in reverse order.
	reader := body
	for index := len(encodings) - 1; index >= 0; index-- {
		decoder, err := newPreambleDecoder(encodings[index], reader)
		if err != nil {
			return io.LimitReader(body, preambleMaxBodySize), false
		}
		reader = decoder
	}
	return io.LimitReader(reader, preambleMaxBodySize), true
}

func newPreambleDecoder(contentEncoding string, body io.Reader) (io.Reader, error) {
	switch contentEncoding {
	case "gzip":
		return gzip.NewReader(body)
	case "deflate":
		// Chromium tries zlib first and falls back to raw deflate.
		head := make([]byte, 2)
		if _, err := io.ReadFull(body, head); err != nil {
			return nil, err
		}
		reader := io.MultiReader(bytes.NewReader(head), body)
		if isZlibHeader(head) {
			return zlib.NewReader(reader)
		}
		return flate.NewReader(reader), nil
	case "br":
		return brotli.NewReader(body), nil
	case "zstd":
		return zstd.NewReader(body)
	}
	return nil, E.New("unknown content encoding: ", contentEncoding)
}

func isZlibHeader(head []byte) bool {
	return len(head) == 2 && head[0]&0x0f == 8 && (int(head[0])<<8|int(head[1]))%31 == 0
}

// Port of PreambleGetter::ExtractLinkAndScriptURLs(). The quirks are
// intentional: prefix-only tag matching, values truncated at the first '>'.
func extractPreambleLinks(html string) []string {
	var results []string
	pos := 0
	for pos < len(html) {
		lt := strings.IndexByte(html[pos:], '<')
		if lt < 0 {
			break
		}
		lt += pos
		gt := strings.IndexByte(html[lt:], '>')
		if gt < 0 {
			break
		}
		gt += lt

		tag := strings.TrimLeft(html[lt+1:gt], " \t\n\v\f\r")

		isLink := startsWithTag(tag, "link")
		isScript := startsWithTag(tag, "script")
		isImg := startsWithTag(tag, "img")
		if !isLink && !isScript && !isImg {
			pos = gt + 1
			continue
		}

		index := 0
		for index < len(tag) {
			for index < len(tag) && isASCIIWhitespace(tag[index]) {
				index++
			}
			nameStart := index
			for index < len(tag) && !isASCIIWhitespace(tag[index]) && tag[index] != '=' {
				index++
			}
			attr := tag[nameStart:index]

			matched := false
			if isLink && strings.EqualFold(attr, "href") {
				matched = true
			} else if isScript && strings.EqualFold(attr, "src") {
				matched = true
			} else if isImg && strings.EqualFold(attr, "src") {
				matched = true
			}
			if matched {
				if value, next, ok := consumeAttrValue(tag, index); ok {
					results = append(results, value)
					index = next
				}
			} else if _, next, ok := consumeAttrValue(tag, index); ok {
				index = next
			} else if index < len(tag) {
				// Advance at least one char to avoid an infinite loop.
				index++
			}
		}
		pos = gt + 1
	}
	return results
}

func isASCIIWhitespace(c byte) bool {
	return c == '\t' || c == '\v' || c == '\f' || c == ' ' || c == '\n' || c == '\r'
}

func startsWithTag(tag, name string) bool {
	return len(tag) >= len(name) && strings.EqualFold(tag[:len(name)], name)
}

func consumeAttrValue(input string, index int) (string, int, bool) {
	pos := index
	for pos < len(input) && isASCIIWhitespace(input[pos]) {
		pos++
	}
	if pos >= len(input) || input[pos] != '=' {
		if pos < len(input) {
			return "", pos + 1, false
		}
		return "", pos, false
	}
	pos++
	for pos < len(input) && isASCIIWhitespace(input[pos]) {
		pos++
	}
	if pos >= len(input) {
		return "", pos, false
	}
	if input[pos] == '"' || input[pos] == '\'' {
		quote := input[pos]
		pos++
		start := pos
		for pos < len(input) && input[pos] != quote {
			pos++
		}
		value := input[start:pos]
		if pos < len(input) {
			pos++
		}
		return value, pos, true
	}
	start := pos
	for pos < len(input) && !isASCIIWhitespace(input[pos]) && input[pos] != '>' {
		pos++
	}
	return input[start:pos], pos, true
}

// Client hints of a chrome-branded build (embedder_support).
type clientHints struct {
	userAgent string
	secCHUA   string
	platform  string
	mobile    string
}

var (
	greaseyChars   = []string{" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"}
	greasedVersion = []string{"8", "99", "24"}
	orders3        = [6][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
)

// Only the major version matters, so this survives Chromium upgrades.
func newClientHints(major int, goos string) clientHints {
	unifiedPlatform := "X11; Linux x86_64"
	platform := "Linux"
	switch goos {
	case "windows":
		unifiedPlatform = "Windows NT 10.0; Win64; x64"
		platform = "Windows"
	case "darwin":
		unifiedPlatform = "Macintosh; Intel Mac OS X 10_15_7"
		platform = "macOS"
	case "android":
		unifiedPlatform = "Linux; Android 10; K"
		platform = "Android"
	case "ios", "tvos":
		unifiedPlatform = "iPhone; CPU iPhone OS 14_0 like Mac OS X"
		platform = "iOS"
	}
	return clientHints{
		// version_info::GetProductNameAndVersionForReducedUserAgent().
		userAgent: F.ToString("Mozilla/5.0 (", unifiedPlatform, ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/", major, ".0.0.0 Safari/537.36"),
		secCHUA:   brandMajorVersionList(major),
		platform:  F.ToString("\"", platform, "\""),
		// naive never enables the mobile user agent switch.
		mobile: "?0",
	}
}

func brandMajorVersionList(major int) string {
	version := strconv.Itoa(major)
	greaseyBrand := F.ToString("Not", greaseyChars[major%len(greaseyChars)], "A",
		greaseyChars[(major+1)%len(greaseyChars)], "Brand")
	greaseyVersion := greasedVersion[major%len(greasedVersion)]
	entries := []string{
		F.ToString("\"", greaseyBrand, "\";v=\"", greaseyVersion, "\""),
		F.ToString("\"Chromium\";v=\"", version, "\""),
		F.ToString("\"Google Chrome\";v=\"", version, "\""),
	}
	order := orders3[major%len(orders3)]
	shuffled := make([]string, len(entries))
	for index, position := range order {
		shuffled[position] = entries[index]
	}
	return strings.Join(shuffled, ", ")
}

// Parses the major component of an engine version, e.g. "154.0.8037.49".
func chromiumMajor(version string) int {
	major, _, _ := strings.Cut(version, ".")
	if parsed, err := strconv.Atoi(major); err == nil && parsed > 0 {
		return parsed
	}
	return fallbackChromiumMajor
}

func (c *NaiveClient) prepareClientHints(engineVersion string) {
	c.hintsOnce.Do(func() {
		c.hints = newClientHints(chromiumMajor(engineVersion), runtime.GOOS)
		if c.preambleUserAgent != "" {
			c.hints.userAgent = c.preambleUserAgent
		}
	})
}
