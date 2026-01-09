// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httputil

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/wangluozhe/chttp"
)

// drainBody reads all of b to memory and then returns two equivalent
// ReadClosers yielding the same bytes.
//
// It returns an error if the initial slurp of all bytes fails. It does not attempt
// to make the returned ReadClosers have identical error-matching behavior.
func drainBody(b io.ReadCloser) (r1, r2 io.ReadCloser, err error) {
	if b == nil || b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return http.NoBody, http.NoBody, nil
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, b, err
	}
	if err = b.Close(); err != nil {
		return nil, b, err
	}
	return io.NopCloser(&buf), io.NopCloser(bytes.NewReader(buf.Bytes())), nil
}

// dumpConn is a net.Conn which writes to Writer and reads from Reader
type dumpConn struct {
	io.Writer
	io.Reader
}

func (c *dumpConn) Close() error                       { return nil }
func (c *dumpConn) LocalAddr() net.Addr                { return nil }
func (c *dumpConn) RemoteAddr() net.Addr               { return nil }
func (c *dumpConn) SetDeadline(t time.Time) error      { return nil }
func (c *dumpConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dumpConn) SetWriteDeadline(t time.Time) error { return nil }

type neverEnding byte

func (b neverEnding) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

// outgoingLength is a copy of the unexported
// (*http.Request).outgoingLength method.
func outgoingLength(req *http.Request) int64 {
	if req.Body == nil || req.Body == http.NoBody {
		return 0
	}
	if req.ContentLength != 0 {
		return req.ContentLength
	}
	return -1
}

// dumpRequestH2 formats the request in a HTTP/2 style (pseudo-headers).
func dumpRequestH2(req *http.Request, body bool) ([]byte, error) {
	var b bytes.Buffer
	var err error
	save := req.Body

	if !body || req.Body == nil {
		req.Body = nil
	} else {
		save, req.Body, err = drainBody(req.Body)
		if err != nil {
			return nil, err
		}
	}

	// 1. Pseudo Headers Logic
	// Default values
	scheme := "https"
	if req.URL != nil && req.URL.Scheme != "" {
		scheme = req.URL.Scheme
	}
	authority := req.Host
	if authority == "" && req.URL != nil {
		authority = req.URL.Host
	}
	path := "/"
	if req.URL != nil {
		path = req.URL.RequestURI()
	}

	pseudos := map[string]string{
		":method":    valueOrDefault(req.Method, "GET"),
		":scheme":    scheme,
		":authority": authority,
		":path":      path,
	}

	// Determine Pseudo Header Order
	// Default order
	pOrder := []string{":method", ":scheme", ":authority", ":path"}
	// Check PHeaderOrderKey
	if v, ok := req.Header[http.PHeaderOrderKey]; ok && len(v) > 0 {
		pOrder = v
	}

	for _, k := range pOrder {
		if val, ok := pseudos[k]; ok && val != "" {
			fmt.Fprintf(&b, "%s: %s\r\n", k, val)
		}
	}

	// 2. Normal Headers Logic
	var keys []string
	// Collect keys excluding excluded ones and magic keys
	for k := range req.Header {
		if reqWriteExcludeHeaderDump[k] {
			continue
		}
		if k == http.HeaderOrderKey || k == http.PHeaderOrderKey || k == http.UnChangedHeaderKey {
			continue
		}
		keys = append(keys, k)
	}

	// Sort Keys
	// Check HeaderOrderKey
	if order, ok := req.Header[http.HeaderOrderKey]; ok && len(order) > 0 {
		var orderedKeys []string
		var otherKeys []string
		orderMap := make(map[string]bool)
		for _, k := range order {
			orderMap[http.CanonicalHeaderKey(k)] = true
		}

		// First, add keys present in the order list
		for _, k := range order {
			// We iterate the 'order' list to preserve its sequence.
			// However, we must ensure the key actually exists in the request headers.
			// Since we only have canonical keys in 'keys', we need to match carefully.
			canonicalK := http.CanonicalHeaderKey(k)
			for _, existingK := range keys {
				// 修改点1：使用 CanonicalHeaderKey 进行比较，兼容 "cookie" 和 "Cookie"
				if http.CanonicalHeaderKey(existingK) == canonicalK {
					orderedKeys = append(orderedKeys, existingK)
					break
				}
			}
		}

		// Then find remaining keys
		for _, k := range keys {
			// 修改点2：检查 map 时也要使用 CanonicalHeaderKey
			if !orderMap[http.CanonicalHeaderKey(k)] {
				otherKeys = append(otherKeys, k)
			}
		}
		sort.Strings(otherKeys)
		keys = append(orderedKeys, otherKeys...)
	} else {
		sort.Strings(keys)
	}

	// Prepare UnChanged Header Map
	unchangedMap := make(map[string]string)
	if unchanged, ok := req.Header[http.UnChangedHeaderKey]; ok {
		for _, v := range unchanged {
			unchangedMap[http.CanonicalHeaderKey(v)] = v
		}
	}

	for _, k := range keys {
		vals := req.Header[k]
		// Determine display key (Lowercase by default for H2, unless UnChangedHeaderKey overrides)
		displayKey := strings.ToLower(k)
		// 修改点3：查找 UnChanged map 时使用 CanonicalHeaderKey
		if orig, ok := unchangedMap[http.CanonicalHeaderKey(k)]; ok {
			displayKey = orig
		}

		for _, v := range vals {
			// Special handling for Cookie splitting in H2
			if strings.EqualFold(displayKey, "cookie") {
				// Split by semicolon and trim spaces to simulate multiple cookie headers
				cookies := strings.Split(v, ";")
				for _, c := range cookies {
					c = strings.TrimSpace(c)
					if c != "" {
						fmt.Fprintf(&b, "%s: %s\r\n", displayKey, c)
					}
				}
			} else {
				fmt.Fprintf(&b, "%s: %s\r\n", displayKey, v)
			}
		}
	}

	io.WriteString(&b, "\r\n")

	// 3. Body
	if req.Body != nil {
		_, err = io.Copy(&b, req.Body)
		if err != nil {
			return nil, err
		}
	}

	req.Body = save
	return b.Bytes(), nil
}

// DumpRequestOut is like [DumpRequest] but for outgoing client requests. It
// includes any headers that the standard [http.Transport] adds, such as
// User-Agent.
func DumpRequestOut(req *http.Request, body bool) ([]byte, error) {
	// 如果是 HTTP/2，直接使用 H2 格式化逻辑，不走 Transport 模拟
	if req.ProtoMajor == 2 {
		return dumpRequestH2(req, body)
	}

	save := req.Body
	dummyBody := false
	if !body {
		contentLength := outgoingLength(req)
		if contentLength != 0 {
			req.Body = io.NopCloser(io.LimitReader(neverEnding('x'), contentLength))
			dummyBody = true
		}
	} else {
		var err error
		save, req.Body, err = drainBody(req.Body)
		if err != nil {
			return nil, err
		}
	}

	// Since we're using the actual Transport code to write the request,
	// switch to http so the Transport doesn't try to do an SSL
	// negotiation with our dumpConn and its bytes.Buffer & pipe.
	// The wire format for https and http are the same, anyway.
	reqSend := req
	if req.URL.Scheme == "https" {
		reqSend = new(http.Request)
		*reqSend = *req
		reqSend.URL = new(url.URL)
		*reqSend.URL = *req.URL
		reqSend.URL.Scheme = "http"
	}

	// Use the actual Transport code to record what we would send
	// on the wire, but not using TCP.  Use a Transport with a
	// custom dialer that returns a fake net.Conn that waits
	// for the full input (and recording it), and then responds
	// with a dummy response.
	var buf bytes.Buffer // records the output
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()
	dr := &delegateReader{c: make(chan io.Reader)}

	t := &http.Transport{
		Dial: func(net, addr string) (net.Conn, error) {
			return &dumpConn{io.MultiWriter(&buf, pw), dr}, nil
		},
	}
	defer t.CloseIdleConnections()

	// We need this channel to ensure that the reader
	// goroutine exits if t.RoundTrip returns an error.
	// See golang.org/issue/32571.
	quitReadCh := make(chan struct{})
	// Wait for the request before replying with a dummy response:
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(pr))
		if err == nil {
			// Ensure all the body is read; otherwise
			// we'll get a partial dump.
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
		}
		select {
		case dr.c <- strings.NewReader("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"):
		case <-quitReadCh:
			// Ensure delegateReader.Read doesn't block forever if we get an error.
			close(dr.c)
		}
	}()

	_, err := t.RoundTrip(reqSend)

	req.Body = save
	if err != nil {
		pw.Close()
		dr.err = err
		close(quitReadCh)
		return nil, err
	}
	dump := buf.Bytes()

	// If we used a dummy body above, remove it now.
	// TODO: if the req.ContentLength is large, we allocate memory
	// unnecessarily just to slice it off here. But this is just
	// a debug function, so this is acceptable for now. We could
	// discard the body earlier if this matters.
	if dummyBody {
		if i := bytes.Index(dump, []byte("\r\n\r\n")); i >= 0 {
			dump = dump[:i+4]
		}
	}
	return dump, nil
}

// delegateReader is a reader that delegates to another reader,
// once it arrives on a channel.
type delegateReader struct {
	c   chan io.Reader
	err error     // only used if r is nil and c is closed.
	r   io.Reader // nil until received from c
}

func (r *delegateReader) Read(p []byte) (int, error) {
	if r.r == nil {
		var ok bool
		if r.r, ok = <-r.c; !ok {
			return 0, r.err
		}
	}
	return r.r.Read(p)
}

// Return value if nonempty, def otherwise.
func valueOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}

var reqWriteExcludeHeaderDump = map[string]bool{
	"Host":              true, // not in Header map anyway
	"Transfer-Encoding": true,
	"Trailer":           true,
}

// DumpRequest returns the given request in its HTTP/1.x wire
// representation. It should only be used by servers to debug client
// requests. The returned representation is an approximation only;
// some details of the initial request are lost while parsing it into
// an [http.Request]. In particular, the order and case of header field
// names are lost. The order of values in multi-valued headers is kept
// intact. HTTP/2 requests are dumped in HTTP/1.x form, not in their
// original binary representations.
//
// If body is true, DumpRequest also returns the body. To do so, it
// consumes req.Body and then replaces it with a new [io.ReadCloser]
// that yields the same bytes. If DumpRequest returns an error,
// the state of req is undefined.
//
// The documentation for [http.Request.Write] details which fields
// of req are included in the dump.
func DumpRequest(req *http.Request, body bool) ([]byte, error) {
	// 如果是 HTTP/2，切换到 H2 格式输出
	if req.ProtoMajor == 2 {
		return dumpRequestH2(req, body)
	}

	var err error
	save := req.Body
	if !body || req.Body == nil {
		req.Body = nil
	} else {
		save, req.Body, err = drainBody(req.Body)
		if err != nil {
			return nil, err
		}
	}

	var b bytes.Buffer

	// By default, print out the unmodified req.RequestURI, which
	// is always set for incoming server requests. But because we
	// previously used req.URL.RequestURI and the docs weren't
	// always so clear about when to use DumpRequest vs
	// DumpRequestOut, fall back to the old way if the caller
	// provides a non-server Request.
	reqURI := req.RequestURI
	if reqURI == "" {
		reqURI = req.URL.RequestURI()
	}

	fmt.Fprintf(&b, "%s %s HTTP/%d.%d\r\n", valueOrDefault(req.Method, "GET"),
		reqURI, req.ProtoMajor, req.ProtoMinor)

	absRequestURI := strings.HasPrefix(req.RequestURI, "http://") || strings.HasPrefix(req.RequestURI, "https://")
	if !absRequestURI {
		host := req.Host
		if host == "" && req.URL != nil {
			host = req.URL.Host
		}
		if host != "" {
			fmt.Fprintf(&b, "Host: %s\r\n", host)
		}
	}

	chunked := len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked"
	if len(req.TransferEncoding) > 0 {
		fmt.Fprintf(&b, "Transfer-Encoding: %s\r\n", strings.Join(req.TransferEncoding, ","))
	}

	err = req.Header.WriteSubset(&b, reqWriteExcludeHeaderDump)
	if err != nil {
		return nil, err
	}

	io.WriteString(&b, "\r\n")

	if req.Body != nil {
		var dest io.Writer = &b
		if chunked {
			dest = NewChunkedWriter(dest)
		}
		_, err = io.Copy(dest, req.Body)
		if chunked {
			dest.(io.Closer).Close()
			io.WriteString(&b, "\r\n")
		}
	}

	req.Body = save
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// errNoBody is a sentinel error value used by failureToReadBody so we
// can detect that the lack of body was intentional.
var errNoBody = errors.New("sentinel error value")

// failureToReadBody is an io.ReadCloser that just returns errNoBody on
// Read. It's swapped in when we don't actually want to consume
// the body, but need a non-nil one, and want to distinguish the
// error from reading the dummy body.
type failureToReadBody struct{}

func (failureToReadBody) Read([]byte) (int, error) { return 0, errNoBody }
func (failureToReadBody) Close() error             { return nil }

// emptyBody is an instance of empty reader.
var emptyBody = io.NopCloser(strings.NewReader(""))

// dumpResponseH2 formats the response in a HTTP/2 style.
func dumpResponseH2(resp *http.Response, body bool) ([]byte, error) {
	var b bytes.Buffer
	var err error
	save := resp.Body

	if !body {
		resp.Body = emptyBody // Not strictly needed here but keeps logic similar
	} else if resp.Body == nil {
		resp.Body = emptyBody
	} else {
		save, resp.Body, err = drainBody(resp.Body)
		if err != nil {
			return nil, err
		}
	}

	// 1. Pseudo Headers Logic
	// :status is the only response pseudo header
	pseudos := map[string]string{
		":status": fmt.Sprintf("%d", resp.StatusCode),
	}
	pOrder := []string{":status"}

	// Check PHeaderOrderKey
	if v, ok := resp.Header[http.PHeaderOrderKey]; ok && len(v) > 0 {
		pOrder = v
	}

	for _, k := range pOrder {
		if val, ok := pseudos[k]; ok {
			fmt.Fprintf(&b, "%s: %s\r\n", k, val)
		}
	}

	// 2. Normal Headers Logic
	var keys []string
	for k := range resp.Header {
		if k == http.HeaderOrderKey || k == http.PHeaderOrderKey || k == http.UnChangedHeaderKey {
			continue
		}
		keys = append(keys, k)
	}

	// Sort Keys
	// Check HeaderOrderKey
	if order, ok := resp.Header[http.HeaderOrderKey]; ok && len(order) > 0 {
		var orderedKeys []string
		var otherKeys []string
		orderMap := make(map[string]bool)
		for _, k := range order {
			orderMap[http.CanonicalHeaderKey(k)] = true
		}

		for _, k := range order {
			canonicalK := http.CanonicalHeaderKey(k)
			for _, existingK := range keys {
				// 修改点1：使用 CanonicalHeaderKey 进行比较
				if http.CanonicalHeaderKey(existingK) == canonicalK {
					orderedKeys = append(orderedKeys, existingK)
					break
				}
			}
		}

		for _, k := range keys {
			// 修改点2：检查 map 时使用 CanonicalHeaderKey
			if !orderMap[http.CanonicalHeaderKey(k)] {
				otherKeys = append(otherKeys, k)
			}
		}
		sort.Strings(otherKeys)
		keys = append(orderedKeys, otherKeys...)
	} else {
		sort.Strings(keys)
	}

	// Prepare UnChanged Header Map
	unchangedMap := make(map[string]string)
	if unchanged, ok := resp.Header[http.UnChangedHeaderKey]; ok {
		for _, v := range unchanged {
			unchangedMap[http.CanonicalHeaderKey(v)] = v
		}
	}

	for _, k := range keys {
		vals := resp.Header[k]
		displayKey := strings.ToLower(k)
		// 修改点3：查找 UnChanged map 时使用 CanonicalHeaderKey
		if orig, ok := unchangedMap[http.CanonicalHeaderKey(k)]; ok {
			displayKey = orig
		}
		for _, v := range vals {
			// Response typically uses Set-Cookie, which is naturally multiple lines in http.Header
			// But if regular Cookie appears (weird in response), we treat it same way
			if strings.EqualFold(displayKey, "cookie") {
				cookies := strings.Split(v, ";")
				for _, c := range cookies {
					c = strings.TrimSpace(c)
					if c != "" {
						fmt.Fprintf(&b, "%s: %s\r\n", displayKey, c)
					}
				}
			} else {
				fmt.Fprintf(&b, "%s: %s\r\n", displayKey, v)
			}
		}
	}

	io.WriteString(&b, "\r\n")

	// 3. Body
	if body && resp.Body != nil {
		_, err = io.Copy(&b, resp.Body)
		if err != nil {
			return nil, err
		}
	}

	resp.Body = save
	return b.Bytes(), nil
}

// DumpResponse is like DumpRequest but dumps a response.
func DumpResponse(resp *http.Response, body bool) ([]byte, error) {
	// 如果是 HTTP/2，切换到 H2 格式输出
	if resp.ProtoMajor == 2 {
		return dumpResponseH2(resp, body)
	}

	var b bytes.Buffer
	var err error
	save := resp.Body
	savecl := resp.ContentLength

	if !body {
		// For content length of zero. Make sure the body is an empty
		// reader, instead of returning error through failureToReadBody{}.
		if resp.ContentLength == 0 {
			resp.Body = emptyBody
		} else {
			resp.Body = failureToReadBody{}
		}
	} else if resp.Body == nil {
		resp.Body = emptyBody
	} else {
		save, resp.Body, err = drainBody(resp.Body)
		if err != nil {
			return nil, err
		}
	}
	err = resp.Write(&b)
	if err == errNoBody {
		err = nil
	}
	resp.Body = save
	resp.ContentLength = savecl
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
