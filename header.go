// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"cmp"
	"io"
	"net/textproto"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/wangluozhe/chttp/httptrace"
	"github.com/wangluozhe/chttp/internal/ascii"
	"github.com/wangluozhe/chttp/internal/httpcommon"

	"golang.org/x/net/http/httpguts"
)

// A Header represents the key-value pairs in an HTTP header.
//
// The keys should be in canonical form, as returned by
// [CanonicalHeaderKey].
type Header map[string][]string

// HeaderOrderKey specifies the order of header names when writing a Header.
// Names are matched case-insensitively. Fields outside the list follow in
// lexicographic order.
const HeaderOrderKey = httpcommon.HeaderOrderKey

// PHeaderOrderKey specifies the order of HTTP/2 request pseudo-headers.
// Required fields outside the list follow in their default order.
const PHeaderOrderKey = httpcommon.PHeaderOrderKey

// UnChangedHeaderKey specifies the spelling of header names on the HTTP/1 wire.
const UnChangedHeaderKey = httpcommon.UnChangedHeaderKey

func (h Header) inUnChangedHeaderKeys(key string) string {
	for _, unKey := range h[UnChangedHeaderKey] {
		if ascii.EqualFold(key, unKey) {
			return unKey
		}
	}
	return key
}

// ContainsUnChangedHeaderKeys reports whether target is listed verbatim.
func (h Header) ContainsUnChangedHeaderKeys(target string) bool {
	return slices.Contains(h[UnChangedHeaderKey], target)
}

// Add adds the key, value pair to the header.
// It appends to any existing values associated with key.
// The key is case insensitive; it is canonicalized by
// [CanonicalHeaderKey].
func (h Header) Add(key, value string) {
	if h.ContainsUnChangedHeaderKeys(key) {
		h[key] = append(h[key], value)
	} else {
		textproto.MIMEHeader(h).Add(key, value)
	}
}

// Set sets the header entries associated with key to the
// single element value. It replaces any existing values
// associated with key. The key is case insensitive; it is
// canonicalized by [textproto.CanonicalMIMEHeaderKey].
// To use non-canonical keys, assign to the map directly.
func (h Header) Set(key, value string) {
	if h.ContainsUnChangedHeaderKeys(key) {
		h[key] = []string{value}
	} else {
		textproto.MIMEHeader(h).Set(key, value)
	}
}

// Get gets the first value associated with the given key. If
// there are no values associated with the key, Get returns "".
// It is case insensitive; [textproto.CanonicalMIMEHeaderKey] is
// used to canonicalize the provided key. Get assumes that all
// keys are stored in canonical form. To use non-canonical keys,
// access the map directly.
func (h Header) Get(key string) string {
	if h.ContainsUnChangedHeaderKeys(key) {
		if h == nil {
			return ""
		}
		v := h[key]
		if len(v) == 0 {
			return ""
		}
		return v[0]
	} else {
		return textproto.MIMEHeader(h).Get(key)
	}
}

// Values returns all values associated with the given key.
// It is case insensitive; [textproto.CanonicalMIMEHeaderKey] is
// used to canonicalize the provided key. To use non-canonical
// keys, access the map directly.
// The returned slice is not a copy.
func (h Header) Values(key string) []string {
	if h.ContainsUnChangedHeaderKeys(key) {
		if h == nil {
			return nil
		}
		return h[key]
	} else {
		return textproto.MIMEHeader(h).Values(key)
	}
}

// get is like Get, but key must already be in CanonicalHeaderKey form.
func (h Header) get(key string) string {
	if v := h[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// has reports whether h has the provided key defined, even if it's
// set to 0-length slice.
func (h Header) has(key string) bool {
	_, ok := h[key]
	return ok
}

// Del deletes the values associated with key.
// The key is case insensitive; it is canonicalized by
// [CanonicalHeaderKey].
func (h Header) Del(key string) {
	if h.ContainsUnChangedHeaderKeys(key) {
		delete(h, key)
	} else {
		textproto.MIMEHeader(h).Del(key)
	}
}

// Write writes a header in wire format.
func (h Header) Write(w io.Writer) error {
	return h.write(w, nil)
}

func (h Header) write(w io.Writer, trace *httptrace.ClientTrace) error {
	return h.writeSubset(w, nil, trace)
}

// Clone returns a copy of h or nil if h is nil.
func (h Header) Clone() Header {
	if h == nil {
		return nil
	}

	// Find total number of values.
	nv := 0
	for _, vv := range h {
		nv += len(vv)
	}
	sv := make([]string, nv) // shared backing array for headers' values
	h2 := make(Header, len(h))
	for k, vv := range h {
		if vv == nil {
			// Preserve nil values. ReverseProxy distinguishes
			// between nil and zero-length header values.
			h2[k] = nil
			continue
		}
		n := copy(sv, vv)
		h2[k] = sv[:n:n]
		sv = sv[n:]
	}
	return h2
}

var timeFormats = []string{
	TimeFormat,
	time.RFC850,
	time.ANSIC,
}

// ParseTime parses a time header (such as the Date: header),
// trying each of the three formats allowed by HTTP/1.1:
// [TimeFormat], [time.RFC850], and [time.ANSIC].
func ParseTime(text string) (t time.Time, err error) {
	for _, layout := range timeFormats {
		t, err = time.Parse(layout, text)
		if err == nil {
			return
		}
	}
	return
}

var headerNewlineToSpace = strings.NewReplacer("\n", " ", "\r", " ")

// stringWriter implements WriteString on a Writer.
type stringWriter struct {
	w io.Writer
}

func (w stringWriter) WriteString(s string) (n int, err error) {
	return w.w.Write([]byte(s))
}

type keyValues struct {
	key    string
	values []string
	rank   int
}

// headerSorter contains a slice of keyValues sorted by keyValues.key.
type headerSorter struct {
	kvs []keyValues
}

var headerSorterPool = sync.Pool{
	New: func() any { return new(headerSorter) },
}

// WriteSubset writes a header in wire format.
// If exclude is not nil, keys where exclude[key] == true are not written.
// Keys are not canonicalized before checking the exclude map.
func (h Header) WriteSubset(w io.Writer, exclude map[string]bool) error {
	return h.writeSubset(w, exclude, nil)
}

func (h Header) writeSubset(w io.Writer, exclude map[string]bool, trace *httptrace.ClientTrace) error {
	return h.writeSorted(w, exclude, nil, trace)
}

// writeSorted includes generated request fields in the same sort as h.
func (h Header) writeSorted(w io.Writer, exclude map[string]bool, generated []keyValues, trace *httptrace.ClientTrace) error {
	ws, ok := w.(io.StringWriter)
	if !ok {
		ws = stringWriter{w}
	}

	sorter := headerSorterPool.Get().(*headerSorter)
	defer func() {
		clear(sorter.kvs)
		sorter.kvs = sorter.kvs[:0]
		headerSorterPool.Put(sorter)
	}()

	order := h[HeaderOrderKey]
	kvs := append(sorter.kvs, generated...)
	for k, vv := range h {
		if exclude[k] || httpcommon.IsHeaderMetadata(k) {
			continue
		}
		if generated != nil && (ascii.EqualFold(k, "host") ||
			ascii.EqualFold(k, "content-length") || ascii.EqualFold(k, "transfer-encoding") ||
			ascii.EqualFold(k, "trailer")) {
			continue
		}
		kvs = append(kvs, keyValues{key: k, values: vv})
	}
	sorter.kvs = kvs
	if len(order) != 0 {
		for i := range kvs {
			kvs[i].rank = httpcommon.HeaderOrderIndex(order, kvs[i].key)
		}
	}
	slices.SortFunc(kvs, func(a, b keyValues) int {
		if a.rank != b.rank {
			return cmp.Compare(a.rank, b.rank)
		}
		return strings.Compare(a.key, b.key)
	})

	var formattedVals []string
	for _, kv := range kvs {
		if !httpguts.ValidHeaderFieldName(kv.key) {
			// This could be an error. In the common case of
			// writing response headers, however, we have no good
			// way to provide the error back to the server
			// handler, so just drop invalid headers instead.
			continue
		}
		key := h.inUnChangedHeaderKeys(kv.key)
		for _, v := range kv.values {
			v = headerNewlineToSpace.Replace(v)
			v = textproto.TrimString(v)
			for _, s := range []string{key, ": ", v, "\r\n"} {
				if _, err := ws.WriteString(s); err != nil {
					return err
				}
			}
			if trace != nil && trace.WroteHeaderField != nil {
				formattedVals = append(formattedVals, v)
			}
		}
		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField(kv.key, formattedVals)
			formattedVals = nil
		}
	}
	return nil
}

// CanonicalHeaderKey returns the canonical format of the
// header key s. The canonicalization converts the first
// letter and any letter following a hyphen to upper case;
// the rest are converted to lowercase. For example, the
// canonical key for "accept-encoding" is "Accept-Encoding".
// If s contains a space or invalid header field bytes, it is
// returned without modifications.
func CanonicalHeaderKey(s string) string { return textproto.CanonicalMIMEHeaderKey(s) }

// hasToken reports whether token appears with v, ASCII
// case-insensitive, with space or comma boundaries.
// token must be all lowercase.
// v may contain mixed cased.
func hasToken(v, token string) bool {
	if len(token) > len(v) || token == "" {
		return false
	}
	if v == token {
		return true
	}
	for sp := 0; sp <= len(v)-len(token); sp++ {
		// Check that first character is good.
		// The token is ASCII, so checking only a single byte
		// is sufficient. We skip this potential starting
		// position if both the first byte and its potential
		// ASCII uppercase equivalent (b|0x20) don't match.
		// False positives ('^' => '~') are caught by EqualFold.
		if b := v[sp]; b != token[0] && b|0x20 != token[0] {
			continue
		}
		// Check that start pos is on a valid token boundary.
		if sp > 0 && !isTokenBoundary(v[sp-1]) {
			continue
		}
		// Check that end pos is on a valid token boundary.
		if endPos := sp + len(token); endPos != len(v) && !isTokenBoundary(v[endPos]) {
			continue
		}
		if ascii.EqualFold(v[sp:sp+len(token)], token) {
			return true
		}
	}
	return false
}

func isTokenBoundary(b byte) bool {
	return b == ' ' || b == ',' || b == '\t'
}
