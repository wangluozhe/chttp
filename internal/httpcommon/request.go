// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpcommon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/textproto"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/wangluozhe/chttp/httptrace"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
)

var (
	ErrRequestHeaderListSize = errors.New("request header list larger than peer's advertised limit")
)

// Request is a subset of http.Request.
// It'd be simpler to pass an *http.Request, of course, but we can't depend on net/http
// without creating a dependency cycle.
type Request struct {
	URL                 *url.URL
	Method              string
	Host                string
	Header              map[string][]string
	Trailer             map[string][]string
	ActualContentLength int64 // 0 means 0, -1 means unknown
}

// EncodeHeadersParam is parameters to EncodeHeaders.
type EncodeHeadersParam struct {
	Request Request

	// AddGzipHeader indicates that an "accept-encoding: gzip" header should be
	// added to the request.
	AddGzipHeader bool

	// PeerMaxHeaderListSize, when non-zero, is the peer's MAX_HEADER_LIST_SIZE setting.
	PeerMaxHeaderListSize uint64

	// DefaultUserAgent is sent when the request has no nonempty User-Agent.
	DefaultUserAgent string
}

// EncodeHeadersResult is the result of EncodeHeaders.
type EncodeHeadersResult struct {
	HasBody     bool
	HasTrailers bool
}

// EncodeHeaders constructs request headers common to HTTP/2 and HTTP/3.
// It validates a request and calls headerf with each pseudo-header and header
// for the request.
// The headerf function is called with the validated, canonicalized header name.
func EncodeHeaders(ctx context.Context, param EncodeHeadersParam, headerf func(name, value string)) (res EncodeHeadersResult, _ error) {
	req := param.Request

	// Check for invalid connection-level headers.
	if err := checkConnHeaders(req.Header); err != nil {
		return res, err
	}

	if req.URL == nil {
		return res, errors.New("Request.URL is nil")
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return res, err
	}
	if !httpguts.ValidHostHeader(host) {
		return res, errors.New("invalid Host header")
	}

	// isNormalConnect is true if this is a non-extended CONNECT request.
	isNormalConnect := false
	var protocol string
	if vv := req.Header[":protocol"]; len(vv) > 0 {
		protocol = vv[0]
	}
	if req.Method == "CONNECT" && protocol == "" {
		isNormalConnect = true
	} else if protocol != "" && req.Method != "CONNECT" {
		return res, errors.New("invalid :protocol header in non-CONNECT request")
	}

	// Validate the path, except for non-extended CONNECT requests which have no path.
	var path string
	if !isNormalConnect {
		path = req.URL.RequestURI()
		if !validPseudoPath(path) {
			orig := path
			path = strings.TrimPrefix(path, req.URL.Scheme+"://"+host)
			if !validPseudoPath(path) {
				if req.URL.Opaque != "" {
					return res, fmt.Errorf("invalid request :path %q from URL.Opaque = %q", orig, req.URL.Opaque)
				} else {
					return res, fmt.Errorf("invalid request :path %q", orig)
				}
			}
		}
	}

	// Check for any invalid headers+trailers and return an error before we
	// potentially pollute our hpack state. (We want to be able to
	// continue to reuse the hpack encoder for future requests)
	if err := validateHeaders(req.Header, true); err != "" {
		return res, fmt.Errorf("invalid HTTP header %s", err)
	}
	if err := validateHeaders(req.Trailer, false); err != "" {
		return res, fmt.Errorf("invalid HTTP trailer %s", err)
	}

	trailers, err := commaSeparatedTrailers(req.Trailer)
	if err != nil {
		return res, err
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}
	var pseudoBuf [5]hpack.HeaderField
	pseudo := append(pseudoBuf[:0],
		hpack.HeaderField{Name: ":authority", Value: host},
		hpack.HeaderField{Name: ":method", Value: method},
	)
	if !isNormalConnect {
		pseudo = append(pseudo,
			hpack.HeaderField{Name: ":path", Value: path},
			hpack.HeaderField{Name: ":scheme", Value: req.URL.Scheme},
		)
	}
	if protocol != "" {
		pseudo = append(pseudo, hpack.HeaderField{Name: ":protocol", Value: protocol})
	}
	if order := req.Header[PHeaderOrderKey]; len(order) > 0 {
		slices.SortStableFunc(pseudo, func(a, b hpack.HeaderField) int {
			return cmp.Compare(HeaderOrderIndex(order, a.Name), HeaderOrderIndex(order, b.Name))
		})
	}

	// Keep the original spelling as the sort key. Lowercase names are used
	// for both the header list size and the encoded HTTP/2 field.
	type field struct {
		key, name string
		values    []string
		value     string // used for generated fields, which have one value
		rank      int
	}
	var fieldBuf [12]field
	fields := fieldBuf[:0]
	order := req.Header[HeaderOrderKey]
	var didUA bool
	for k, vv := range req.Header {
		if len(vv) == 0 || IsHeaderMetadata(k) || k == ":protocol" {
			continue
		}
		name, _ := LowerHeader(k)
		switch name {
		case "host", "content-length":
			// :authority and the generated content-length take precedence.
			continue
		case "connection", "proxy-connection", "transfer-encoding", "upgrade", "keep-alive":
			continue
		case "user-agent":
			if vv[0] == "" {
				continue
			}
			didUA = true
			vv = vv[:1]
		}
		fields = append(fields, field{key: k, name: name, values: vv, rank: HeaderOrderIndex(order, name)})
	}
	if shouldSendReqContentLength(req.Method, req.ActualContentLength) {
		const name = "content-length"
		fields = append(fields, field{key: name, name: name, value: strconv.FormatInt(req.ActualContentLength, 10), rank: HeaderOrderIndex(order, name)})
	}
	if param.AddGzipHeader {
		const name = "accept-encoding"
		fields = append(fields, field{key: name, name: name, value: "gzip", rank: HeaderOrderIndex(order, name)})
	}
	if !didUA && param.DefaultUserAgent != "" {
		const name = "user-agent"
		fields = append(fields, field{key: name, name: name, value: param.DefaultUserAgent, rank: HeaderOrderIndex(order, name)})
	}
	slices.SortFunc(fields, func(a, b field) int {
		if a.rank != b.rank {
			return cmp.Compare(a.rank, b.rank)
		}
		return strings.Compare(a.key, b.key)
	})

	enumerateHeaders := func(f func(name, value string)) {
		for _, field := range pseudo {
			f(field.Name, field.Value)
		}
		if trailers != "" {
			f("trailer", trailers)
		}
		for _, field := range fields {
			if field.values == nil {
				f(field.name, field.value)
				continue
			}
			if field.name == "cookie" {
				// Per 8.1.2.5 To allow for better compression efficiency, the
				// Cookie header field MAY be split into separate header fields,
				// each with one or more cookie-pairs.
				for _, v := range field.values {
					for {
						p := strings.IndexByte(v, ';')
						if p < 0 {
							break
						}
						f("cookie", v[:p])
						p++
						// strip space after semicolon if any.
						for p+1 <= len(v) && v[p] == ' ' {
							p++
						}
						v = v[p:]
					}
					if len(v) > 0 {
						f("cookie", v)
					}
				}
				continue
			}

			for _, v := range field.values {
				f(field.name, v)
			}
		}
	}

	// Do a first pass over the headers counting bytes to ensure
	// we don't exceed cc.peerMaxHeaderListSize. This is done as a
	// separate pass before encoding the headers to prevent
	// modifying the hpack state.
	if param.PeerMaxHeaderListSize > 0 {
		hlSize := uint64(0)
		enumerateHeaders(func(name, value string) {
			hf := hpack.HeaderField{Name: name, Value: value}
			hlSize += uint64(hf.Size())
		})

		if hlSize > param.PeerMaxHeaderListSize {
			return res, ErrRequestHeaderListSize
		}
	}

	trace := httptrace.ContextClientTrace(ctx)

	// Header list size is ok. Write the headers.
	enumerateHeaders(func(name, value string) {
		headerf(name, value)

		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField(name, []string{value})
		}
	})

	res.HasBody = req.ActualContentLength != 0
	res.HasTrailers = trailers != ""
	return res, nil
}

// IsRequestGzip reports whether we should add an Accept-Encoding: gzip header
// for a request.
func IsRequestGzip(method string, header map[string][]string, disableCompression bool) bool {
	if !disableCompression &&
		method != "HEAD" &&
		!headerKeyExists(header, "Accept-Encoding") &&
		!headerKeyExists(header, "Range") {
		// Request gzip only, not deflate. Deflate is ambiguous and
		// not as universally supported anyway.
		// See: https://zlib.net/zlib_faq.html#faq39
		//
		// Note that we don't request this for HEAD requests,
		// due to a bug in nginx:
		//   http://trac.nginx.org/nginx/ticket/358
		//   https://golang.org/issue/5522
		//
		// We don't request gzip if the request is for a range, since
		// auto-decoding a portion of a gzipped document will just fail
		// anyway. See https://golang.org/issue/8923
		return true
	}
	return false
}

func headerKeyExists(header map[string][]string, name string) bool {
	if _, ok := header[name]; ok {
		return true
	}
	for key := range header {
		if asciiEqualFold(key, name) {
			return true
		}
	}
	return false
}

// checkConnHeaders checks whether req has any invalid connection-level headers.
//
// https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2-3
// https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2-1
//
// Certain headers are special-cased as okay but not transmitted later.
// For example, we allow "Transfer-Encoding: chunked", but drop the header when encoding.
func checkConnHeaders(h map[string][]string) error {
	if vv := h["Upgrade"]; len(vv) > 0 && (vv[0] != "" && vv[0] != "chunked") {
		return fmt.Errorf("invalid Upgrade request header: %q", vv)
	}
	if vv := h["Transfer-Encoding"]; len(vv) > 0 && (len(vv) > 1 || vv[0] != "" && vv[0] != "chunked") {
		return fmt.Errorf("invalid Transfer-Encoding request header: %q", vv)
	}
	if vv := h["Connection"]; len(vv) > 0 && (len(vv) > 1 || vv[0] != "" && !asciiEqualFold(vv[0], "close") && !asciiEqualFold(vv[0], "keep-alive")) {
		return fmt.Errorf("invalid Connection request header: %q", vv)
	}
	return nil
}

func commaSeparatedTrailers(trailer map[string][]string) (string, error) {
	keys := make([]string, 0, len(trailer))
	for k := range trailer {
		if IsHeaderMetadata(k) {
			continue
		}
		k = CanonicalHeader(k)
		switch k {
		case "Transfer-Encoding", "Trailer", "Content-Length":
			return "", fmt.Errorf("invalid Trailer key %q", k)
		}
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		sort.Strings(keys)
		return strings.Join(keys, ","), nil
	}
	return "", nil
}

// validPseudoPath reports whether v is a valid :path pseudo-header
// value. It must be either:
//
//   - a non-empty string starting with '/'
//   - the string '*', for OPTIONS requests.
//
// For now this is only used a quick check for deciding when to clean
// up Opaque URLs before sending requests from the Transport.
// See golang.org/issue/16847
//
// We used to enforce that the path also didn't start with "//", but
// Google's GFE accepts such paths and Chrome sends them, so ignore
// that part of the spec. See golang.org/issue/19103.
func validPseudoPath(v string) bool {
	return (len(v) > 0 && v[0] == '/') || v == "*"
}

func validateHeaders(hdrs map[string][]string, allowProtocol bool) string {
	for k, vv := range hdrs {
		if IsHeaderMetadata(k) {
			continue
		}
		if !httpguts.ValidHeaderFieldName(k) && !(allowProtocol && k == ":protocol") {
			return fmt.Sprintf("name %q", k)
		}
		for _, v := range vv {
			if !httpguts.ValidHeaderFieldValue(v) {
				// Don't include the value in the error,
				// because it may be sensitive.
				return fmt.Sprintf("value for header %q", k)
			}
		}
	}
	return ""
}

// shouldSendReqContentLength reports whether we should send
// a "content-length" request header. This logic is basically a copy of the net/http
// transferWriter.shouldSendContentLength.
// The contentLength is the corrected contentLength (so 0 means actually 0, not unknown).
// -1 means unknown.
func shouldSendReqContentLength(method string, contentLength int64) bool {
	if contentLength > 0 {
		return true
	}
	if contentLength < 0 {
		return false
	}
	// For zero bodies, whether we send a content-length depends on the method.
	// It also kinda doesn't matter for http2 either way, with END_STREAM.
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// ServerRequestParam is parameters to NewServerRequest.
type ServerRequestParam struct {
	Method                  string
	Scheme, Authority, Path string
	Protocol                string
	Header                  map[string][]string
}

// ServerRequestResult is the result of NewServerRequest.
type ServerRequestResult struct {
	// Various http.Request fields.
	Host       string
	URL        *url.URL
	RequestURI string
	Trailer    map[string][]string

	NeedsContinue bool // client provided an "Expect: 100-continue" header

	// If the request should be rejected, this is a short string suitable for passing
	// to the http2 package's CountError function.
	// It might be a bit odd to return errors this way rather than returning an error,
	// but this ensures we don't forget to include a CountError reason.
	InvalidReason string
}

func NewServerRequest(rp ServerRequestParam) ServerRequestResult {
	needsContinue := httpguts.HeaderValuesContainsToken(rp.Header["Expect"], "100-continue")
	if needsContinue {
		delete(rp.Header, "Expect")
	}
	// Merge Cookie headers into one "; "-delimited value.
	if cookies := rp.Header["Cookie"]; len(cookies) > 1 {
		rp.Header["Cookie"] = []string{strings.Join(cookies, "; ")}
	}

	// Setup Trailers
	var trailer map[string][]string
	for _, v := range rp.Header["Trailer"] {
		for _, key := range strings.Split(v, ",") {
			key = textproto.CanonicalMIMEHeaderKey(textproto.TrimString(key))
			switch key {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				// Bogus. (copy of http1 rules)
				// Ignore.
			default:
				if trailer == nil {
					trailer = make(map[string][]string)
				}
				trailer[key] = nil
			}
		}
	}
	delete(rp.Header, "Trailer")

	authority := rp.Authority
	if host := rp.Header["Host"]; len(host) == 1 {
		// HTTP/2 and HTTP/3 permit the Host header to be present,
		// but it must match the :authority pseudo-header.
		if authority == "" {
			authority = host[0]
		} else if host[0] != authority {
			return ServerRequestResult{
				InvalidReason: "authority_host_mismatch",
			}
		}
		delete(rp.Header, "Host")
	} else if len(host) > 1 {
		// HTTP/1.1 rejects any request containing more than one Host header.
		// HTTP/2 and HTTP/3 don't use the Host header, but reject multiple anyway.
		return ServerRequestResult{
			InvalidReason: "multiple_host_headers",
		}
	}

	// "':authority' MUST NOT include the deprecated userinfo subcomponent
	// for "http" or "https" schemed URIs."
	// https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1-2.3.8
	if strings.IndexByte(authority, '@') != -1 && (rp.Scheme == "http" || rp.Scheme == "https") {
		return ServerRequestResult{
			InvalidReason: "userinfo_in_authority",
		}
	}

	if authority != "" && !httpguts.ValidHostHeader(authority) {
		return ServerRequestResult{
			InvalidReason: "invalid_authority",
		}
	}

	var url_ *url.URL
	var requestURI string
	if rp.Method == "CONNECT" && rp.Protocol == "" {
		url_ = &url.URL{Host: authority}
		requestURI = authority // mimic HTTP/1 server behavior
	} else {
		// "[The :path] pseudo-header field MUST NOT be empty [...]"
		// https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1-2.4.2
		if rp.Path == "" || (rp.Path[0] != '/' && rp.Path != "*") {
			return ServerRequestResult{
				InvalidReason: "bad_path",
			}
		}

		var err error
		url_, err = url.ParseRequestURI(rp.Path)
		if err != nil {
			return ServerRequestResult{
				InvalidReason: "bad_path",
			}
		}
		requestURI = rp.Path
	}

	return ServerRequestResult{
		Host:          authority,
		URL:           url_,
		NeedsContinue: needsContinue,
		RequestURI:    requestURI,
		Trailer:       trailer,
	}
}
