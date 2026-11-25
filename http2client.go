// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !nethttpomithttp2 && !nethttpomithttp2client

package http

import (
	"context"
	"errors"
	"net"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/wangluozhe/chttp/internal/http2"

	_ "unsafe" // for go:linkname
)

// This file connects the net/http Transport to the HTTP/2 client
// in the net/http/internal/http2 package. It is omitted when
// the nethttpomithttp2 or nethttpomithttp2client build tag is set.

const omitHTTP2Client = false

type http2Transport = http2.Transport

type HTTP2Setting = http2.Setting
type HTTP2SettingID = http2.SettingID
type HTTP2PriorityFrame = http2.PriorityFrame
type HTTP2PriorityParam = http2.PriorityParam
type HTTP2FrameHeader = http2.FrameHeader
type HTTP2Settings = http2.HTTP2Settings
type HTTP2Transport = http2.Transport

const (
	HTTP2SettingHeaderTableSize      = http2.SettingHeaderTableSize
	HTTP2SettingEnablePush           = http2.SettingEnablePush
	HTTP2SettingMaxConcurrentStreams = http2.SettingMaxConcurrentStreams
	HTTP2SettingInitialWindowSize    = http2.SettingInitialWindowSize
	HTTP2SettingMaxFrameSize         = http2.SettingMaxFrameSize
	HTTP2SettingMaxHeaderListSize    = http2.SettingMaxHeaderListSize
)

// HTTP2ConfigureTransports enables bundled HTTP/2 on t and returns its
// configuration. Explicit Transport.Protocols and ForceHTTP1 take precedence.
// Call it before using t.
func HTTP2ConfigureTransports(t *Transport) (*HTTP2Transport, error) {
	var protocols Protocols
	if t.Protocols != nil || t.ForceHTTP1 {
		protocols = t.protocols()
	} else {
		protocols.SetHTTP1(true)
		protocols.SetHTTP2(true)
	}
	t.configureHTTP2(protocols)
	return t.h2Transport, nil
}

func (t *Transport) cloneHTTP2(dst *Transport) {
	if t.h2Transport == nil {
		return
	}
	dst.h2Transport = t.h2Transport.CloneFor(transportConfig{dst})
	dst.H2Transport = dst.h2Transport
}

func (t *Transport) closeLegacyHTTP2IdleConnections() {
	if _, bundled := t.H2Transport.(*http2.Transport); !bundled && t.H2Transport != nil {
		t.H2Transport.CloseIdleConnections()
	}
}

// http2ExternalTransportConfig is an HTTP/2 configuration provided by x/net/http2.
//
// When a x/net/http2.Transport wraps a net/http.Transport, we need to support the user
// setting configuration settings on the x/net Transport:
//
//	tr1 := &http.Transport{}
//	tr2 := http2.ConfigureTransports(t1)
//
//	// This setting needs to affect tr1:
//	tr2.MaxHeaderListSize = 10000
//
// We handle this by having http2.ConfigureTransports pass us an http2ExternalTransportConfig,
// which we can use to query the current state of the http2.Transport.
type http2ExternalTransportConfig interface {
	// Various configuration settings:
	HTTP2Config() HTTP2Config
	DisableCompression() bool
	MaxHeaderListSize() int64
	IdleConnTimeout() time.Duration

	// ConnFromContext is used to pass a net.Conn to Transport.NewClientConn
	// via a context value. See Transport.http2NewClientConnFromContext.
	ConnFromContext(context.Context) net.Conn

	// DialFromContext is used to dial new connections, overriding Transport.DialContext etc.
	// This is used when the user calls x/net/http2.Transport.RoundTrip directly,
	// in which case the historical behavior is to use the http2.Transport's dial functions.
	DialFromContext(ctx context.Context, network, addr string) (net.Conn, error)

	// ExternalRoundTrip reports whether Transport.RoundTrip should call the
	// external transport's RoundTrip. This is used when x/net/http2.Transport.ConnPool
	// is set, in which case the user-provided ClientConnPool has taken responsibility
	// for picking a connection to use.
	ExternalRoundTrip() bool

	// RoundTrip performs a round trip.
	// It should only be used when ExternalRoundTrip requests it.
	RoundTrip(*Request) (*Response, error)

	// Registered is called to report successful registration of the config.
	Registered(*Transport)
}

func (t *Transport) configureHTTP2(protocols Protocols) {
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{}
	}
	if t.HTTP2 == nil {
		t.HTTP2 = &HTTP2Config{}
	}
	if t2, ok := t.H2Transport.(*http2.Transport); ok && t2 != nil && t2 != t.h2Transport {
		t2.SetTransportConfig(transportConfig{t})
		t.h2Transport = t2
	} else if t.h2Transport == nil {
		t2 := http2.NewTransport(transportConfig{t})
		t2.AllowHTTP = true
		t.h2Transport = t2
		if t.H2Transport == nil {
			t.H2Transport = t2
		}
	}

	if t.TLSNextProto == nil {
		t.TLSNextProto = make(map[string]func(authority string, c *tls.UConn) RoundTripper)
	}
	// Historically, the presence of a TLSNextProto["h2"] key has been the signal to
	// enable/disable HTTP/2 support. Set a value in the map, but we'll never use it.
	if !protocols.HTTP2() && !protocols.UnencryptedHTTP2() {
		delete(t.TLSNextProto, "h2")
	} else {
		t.TLSNextProto["h2"] = func(authority string, c *tls.UConn) RoundTripper {
			return http2ErringRoundTripper{
				errors.New("unexpected use of stub RoundTripper"),
			}
		}
	}

	// Server.ServeTLS clones the tls.Config before modifying it.
	// Transport doesn't. We may want to make the two consistent some day.
	//
	// http2configureTransport will have already set NextProtos, but adjust it again
	// here to remove HTTP/1.1 if the user has disabled it.
	t.TLSClientConfig.NextProtos = adjustNextProtos(t.TLSClientConfig.NextProtos, protocols)
}

func (t *Transport) legacyHTTP2StrictConcurrency() bool {
	return t.h2Transport != nil && t.h2Transport.StrictMaxConcurrentStreams
}

func (t *Transport) legacyHTTP2IdleTimeout() time.Duration {
	if t.h2Transport != nil {
		return t.h2Transport.IdleConnTimeout
	}
	return 0
}

func (t *Transport) registerHTTP2Config() {
	t.h2Config.Registered(t)
	if f, ok := t.h2Config.(interface {
		GetClientConnStateFunc(func(*ClientConn) any)
	}); ok {
		f.GetClientConnStateFunc(http2GetClientConnState)
	}
}

// http2GetClientConnState is a function x/net/http2 can call to get some additional
// state the ClientConn API doesn't currently provide.
func http2GetClientConnState(cc *ClientConn) any {
	if c, ok := cc.cc.(http2ClientConn); ok {
		return c.NetHTTPClientConn.State()
	}
	return nil
}

type http2ErringRoundTripper struct{ err error }

func (rt http2ErringRoundTripper) RoundTripErr() error                   { return rt.err }
func (rt http2ErringRoundTripper) RoundTrip(*Request) (*Response, error) { return nil, rt.err }

func http2RoundTrip(req *Request, rt func(*http2.ClientRequest) (*http2.ClientResponse, error)) (*Response, error) {
	resp := &Response{}
	cresp, err := rt(&http2.ClientRequest{
		Context:       req.Context(),
		Method:        req.Method,
		URL:           req.URL,
		Header:        http2.Header(req.Header),
		Trailer:       http2.Header(req.Trailer),
		Body:          req.Body,
		Host:          req.Host,
		ContentLength: req.ContentLength,
		Cancel:        req.Cancel,
		Close:         req.Close,
		ResTrailer:    (*http2.Header)(&resp.Trailer),
	})
	if err != nil {
		return nil, err
	}
	resp.Status = cresp.Status + " " + StatusText(cresp.StatusCode)
	resp.StatusCode = cresp.StatusCode
	resp.Proto = "HTTP/2.0"
	resp.ProtoMajor = 2
	resp.ProtoMinor = 0
	resp.ContentLength = cresp.ContentLength
	resp.Uncompressed = cresp.Uncompressed
	resp.Header = Header(cresp.Header)
	resp.Trailer = Header(cresp.Trailer)
	resp.Body = cresp.Body
	resp.TLS = cresp.TLS
	resp.Request = req
	return resp, nil
}

func (t *Transport) http2NewClientConn(nc net.Conn, isClientConn bool, internalStateHook func() error) (genericClientConn, error) {
	if t.h2Transport == nil {
		return nil, errors.ErrUnsupported
	}
	cc, err := t.h2Transport.NewClientConn(nc, isClientConn, internalStateHook)
	if err != nil {
		return nil, err
	}
	return http2ClientConn{cc}, nil
}

// http2NewClientConnFromContext creates a *ClientConn from a net.Conn.
//
// Transport.NewClientConn takes an address and dials a new net.Conn.
// We don't currently provide a simple way for the user to provide a net.Conn and get a
// *ClientConn out of it (although we do let the user provide their own Transport.DialContext,
// which can be used to effectively do this).
//
// x/net/http2.Transport.NewClientConn, in contrast, requires the user to provide a net.Conn.
// To support implementing the x/net/http2 NewClientConn in terms of a net/http.Transport,
// we permit x/net/http2 to pass us a net.Conn via a context key.
//
// http2NewClientConnFromContext handles extracting the net.Conn from the Context
// (when present) and creating a *ClientConn from it.
func (t *Transport) http2NewClientConnFromContext(ctx context.Context) (*ClientConn, error) {
	if t.h2Config == nil {
		return nil, errors.ErrUnsupported
	}
	nc := t.h2Config.ConnFromContext(ctx)
	if nc == nil {
		return nil, errors.ErrUnsupported
	}
	if t.h2Transport == nil {
		return nil, errors.New("http: Transport does not support HTTP/2")
	}
	cc := &ClientConn{}
	const isClientConn = true
	gc, err := t.http2NewClientConn(nc, isClientConn, cc.maybeRunStateHook)
	if err != nil {
		return nil, err
	}
	cc.stateHookMu.Lock()
	defer cc.stateHookMu.Unlock()
	cc.cc = gc
	cc.lastAvailable = gc.Available()
	return cc, nil
}

// http2ExternalDial creates a new HTTP/2 connection,
// using the x/net/http2.Transport's dial functions.
//
// This is used when the user has called x/net/http2.Transport.RoundTrip.
// If the RoundTrip needs to create a new connection,
// the historical behavior is for it to use the http2.Transport's DialTLS or DialTLSContext
// functions, and not any dial functions on the http.Transport.
func (t *Transport) http2ExternalDial(ctx context.Context, cm connectMethod, isClientConn bool, internalStateHook func() error) (genericClientConn, error) {
	if t.h2Config == nil {
		return nil, errors.ErrUnsupported
	}
	nc, err := t.h2Config.DialFromContext(ctx, "tcp", cm.targetAddr)
	if err != nil {
		return nil, err
	}
	return t.http2NewClientConn(nc, isClientConn, internalStateHook)
}

type http2ClientConn struct {
	http2.NetHTTPClientConn
}

func (cc http2ClientConn) RoundTrip(req *Request) (*Response, error) {
	return http2RoundTrip(req, cc.NetHTTPClientConn.RoundTrip)
}

// transportConfig implements the http2.TransportConfig interface,
// providing the net/http Transport's configuration to the HTTP/2 implementation.
//
// When an x/net/http2 Transport has provided a configuration (see http2ExternalTransportConfig),
// the transportConfig merges the x/net/http2 and net/http Transport configurations.
type transportConfig struct {
	t *Transport
}

func (t transportConfig) MaxResponseHeaderBytes() int64        { return t.t.MaxResponseHeaderBytes }
func (t transportConfig) ExpectContinueTimeout() time.Duration { return t.t.ExpectContinueTimeout }
func (t transportConfig) ResponseHeaderTimeout() time.Duration { return t.t.ResponseHeaderTimeout }
func (t transportConfig) CloseIdleConnections()                { t.t.CloseIdleConnections() }

func (t transportConfig) MaxHeaderListSize() int64 {
	if t.t.h2Config != nil {
		return t.t.h2Config.MaxHeaderListSize()
	}
	return 0
}

func (t transportConfig) DisableCompression() bool {
	if t.t.h2Config != nil && t.t.h2Config.DisableCompression() {
		return true
	}
	return t.t.DisableCompression
}

func (t transportConfig) HTTP2Config() http2.Config {
	return mergeHTTP2Config(t.t.HTTP2, t.t.h2Config)
}

// transportFromH1Transport provides a way for HTTP/2 tests to extract
// the http2.Transport from an http.Transport.
//
//go:linkname transportFromH1Transport github.com/wangluozhe/chttp/internal/http2_test.transportFromH1Transport
func transportFromH1Transport(t *Transport) any {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	return t.h2Transport
}
