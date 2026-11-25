//go:build !nethttpomithttp2 && !nethttpomithttp2client

package http

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/wangluozhe/chttp/internal"
	"github.com/wangluozhe/chttp/internal/http2"
	"github.com/wangluozhe/chttp/internal/testcert"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/net/http2/hpack"
)

func TestTransportWire(t *testing.T) {
	cert, roots := wireCredentials(t)
	var fixedHello []byte
	for _, test := range []struct {
		name        string
		useTLS, h2  bool
		custom      bool
		requestBody bool
		replay      bool
		forceHTTP1  bool
		onlyALPN    string
	}{
		{name: "HTTP1"},
		{name: "DefaultHTTP2", useTLS: true, h2: true},
		{name: "FixedJA3", useTLS: true, h2: true, custom: true},
		{name: "RandomJA3", useTLS: true, h2: true, custom: true},
		{name: "Replay", useTLS: true, h2: true, custom: true, replay: true},
		{name: "ForceHTTP1", useTLS: true, custom: true, forceHTTP1: true},
		{name: "PriorityStreamID", useTLS: true, h2: true, custom: true},
		{name: "HTTP1Body", requestBody: true},
		{name: "HTTP2Body", useTLS: true, h2: true, custom: true, requestBody: true},
		{name: "JA3HTTP1Only", useTLS: true, custom: true, onlyALPN: "http/1.1"},
		{name: "JA3HTTP2Only", useTLS: true, h2: true, custom: true, onlyALPN: "h2"},
		{name: "ReplayHTTP1Only", useTLS: true, custom: true, replay: true, onlyALPN: "http/1.1"},
		{name: "ReplayHTTP2Only", useTLS: true, h2: true, custom: true, replay: true, onlyALPN: "h2"},
		{name: "ReplayForceHTTP1", useTLS: true, custom: true, replay: true, forceHTTP1: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			useTLS, h2, custom := test.useTLS, test.h2, test.custom
			transport := &Transport{TLSClientConfig: &utls.Config{RootCAs: roots, ServerName: "example.com"}}
			transport.ForceHTTP1 = test.forceHTTP1
			if !custom || test.onlyALPN != "" {
				transport.Protocols = new(Protocols)
				transport.Protocols.SetHTTP1(test.onlyALPN != "h2")
				transport.Protocols.SetHTTP2(h2)
			}
			firstStream := 9
			if custom {
				configured := configureBenchmarkJA3(t, transport)
				// This is the configuration pattern used by the examples.
				transport.H2Transport = configured
				if h2 {
					settings := configured.HTTP2Settings
					settings.SettingsAck = true
					settings.HeadersID = firstStream
					settings.PriorityFrames = []HTTP2PriorityFrame{{
						HTTP2FrameHeader:   HTTP2FrameHeader{StreamID: 3},
						HTTP2PriorityParam: HTTP2PriorityParam{Weight: 15},
					}}
					if test.name == "PriorityStreamID" {
						settings.HeadersID = 0
						firstStream = 5
					}
				}
			}
			transport.RandomJA3 = test.name == "RandomJA3"
			if test.replay {
				if len(fixedHello) == 0 {
					fixed := &Transport{TLSClientConfig: &utls.Config{RootCAs: roots, ServerName: "example.com"}}
					configureBenchmarkJA3(t, fixed)
					fixedHello = captureTransportWire(t, cert, fixed, true, true, false, false).rawHello
				}
				transport.TLSExtensions.ClientHelloHexStream = hex.EncodeToString(fixedHello)
			}
			got := captureTransportWire(t, cert, transport, useTLS, h2, test.name != "DefaultHTTP2", test.requestBody)
			if useTLS {
				hello := parseWireClientHello(t, got.rawHello)
				t.Logf("wire hello %+v negotiated=%04x/%04x/%q", hello, got.state.Version, got.state.CipherSuite, got.state.NegotiatedProtocol)
				wantALPN := "http/1.1"
				if h2 {
					wantALPN = "h2"
				}
				if got.state.NegotiatedProtocol != wantALPN || got.state.Version != tls.VersionTLS13 {
					t.Fatalf("negotiated TLS = %04x/%q, want TLS 1.3/%q", got.state.Version, got.state.NegotiatedProtocol, wantALPN)
				}
				if custom {
					advertised := test.onlyALPN
					if test.forceHTTP1 {
						advertised = "http/1.1"
					} else if advertised == "" {
						advertised = "h2,http/1.1"
					}
					checkWireJA3(t, hello, advertised, transport.RandomJA3)
				} else if hello.ALPN != "h2,http/1.1" || hello.ServerName != "example.com" {
					t.Fatalf("default ClientHello = %+v", hello)
				}
				if test.name == "FixedJA3" {
					fixedHello = got.rawHello
				}
				if transport.RandomJA3 {
					// Exercise the shuffle without depending on any particular permutation.
					changed := false
					for range 4 {
						another := captureTransportWire(t, cert, transport, true, true, true, false)
						other := parseWireClientHello(t, another.rawHello)
						checkWireJA3(t, other, "h2,http/1.1", true)
						if !slices.Equal(other.Extensions, hello.Extensions) {
							changed = true
							break
						}
					}
					if !changed {
						t.Fatal("RandomJA3 sent the same extension order on five connections")
					}
				}
			}
			for _, frame := range got.frames {
				t.Logf("wire %s", frame)
			}
			want := wireHTTP1Lines(test.requestBody)
			if h2 {
				want = wireHTTP2Frames(custom, firstStream, test.requestBody)
			}
			if !slices.Equal(got.frames, want) {
				t.Fatalf("wire:\n%s\nwant:\n%s", strings.Join(got.frames, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

func wireCredentials(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	cert, err := tls.X509KeyPair(testcert.LocalhostCert, testcert.LocalhostKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(testcert.LocalhostCert) {
		t.Fatal("could not load test certificate")
	}
	return cert, roots
}

type wireResult struct {
	rawHello []byte
	state    tls.ConnectionState
	frames   []string
	err      error
}

func captureTransportWire(t *testing.T, cert tls.Certificate, transport *Transport, useTLS, h2, customHeaders, requestBody bool) wireResult {
	t.Helper()
	defer transport.CloseIdleConnections()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := make(chan wireResult, 1)
	go func() {
		var got wireResult
		defer func() { server <- got }()
		conn, err := listener.Accept()
		if err != nil {
			got.err = err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if useTLS {
			capture := &wireTLSConn{Conn: conn, capture: true}
			tlsConn := tls.Server(capture, &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"h2", "http/1.1"},
			})
			got.err = tlsConn.Handshake()
			got.rawHello = capture.hello.Bytes()
			if got.err != nil {
				return
			}
			capture.capture = false
			got.state = tlsConn.ConnectionState()
			conn = tlsConn
		}
		if h2 {
			got.frames, got.err = serveWireHTTP2(conn)
		} else {
			got.frames, got.err = serveWireHTTP1(conn)
		}
	}()

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	client := &Client{Transport: transport, Timeout: 5 * time.Second}
	var clientState *utls.ConnectionState
	for i := range 2 {
		method := MethodGet
		var body io.Reader
		chunked := requestBody && !h2 && i == 1
		if requestBody {
			method = MethodPost
			body = strings.NewReader("payload")
			if chunked {
				body = io.NopCloser(body) // No known ContentLength.
			}
		}
		req, err := NewRequest(method, scheme+"://"+listener.Addr().String()+"/wire?q=1", body)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "example.com"
		req.Header = Header{"Z-Last": {"z"}, "X-First": {"a", "b"}, "Cookie": {"a=1; b=2"}, "User-Agent": {"wire-test"}}
		if customHeaders {
			req.Header[HeaderOrderKey] = []string{"X-first", "cookie", "host", "user-agent"}
			req.Header[PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
			req.Header[UnChangedHeaderKey] = []string{"x-FIRST"}
		}
		if !h2 {
			req.Header.Set("Host", "wire.example.com")
		}
		if requestBody {
			req.Header.Del("User-Agent")
			req.Header[HeaderOrderKey] = []string{"X-first", "cookie", "host", "content-length", "transfer-encoding", "user-agent"}
			if chunked {
				req.Trailer = Header{"X-Trailer": {"end"}}
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		wantProto := "HTTP/1.1"
		if h2 {
			wantProto = "HTTP/2.0"
		}
		if resp.Proto != wantProto || resp.StatusCode != StatusNoContent {
			t.Fatalf("response = %s %d, want %s 204", resp.Proto, resp.StatusCode, wantProto)
		}
		clientState = resp.TLS
		if useTLS && (clientState == nil || !clientState.HandshakeComplete || len(clientState.VerifiedChains) == 0) {
			t.Fatalf("response is missing verified TLS state: %+v", clientState)
		}
	}

	got := <-server
	if got.err != nil {
		t.Fatal(got.err)
	}
	if useTLS && (clientState.Version != got.state.Version || clientState.CipherSuite != got.state.CipherSuite || clientState.NegotiatedProtocol != got.state.NegotiatedProtocol) {
		t.Fatal("response TLS state disagrees with the server")
	}
	return got
}

func wireHTTP1Lines(requestBody bool) []string {
	if requestBody {
		return []string{
			"POST /wire?q=1 HTTP/1.1", "x-FIRST: a", "x-FIRST: b", "Cookie: a=1; b=2",
			"Host: wire.example.com", "Content-Length: 7", "User-Agent: Go-http-client/1.1", "Z-Last: z", "Accept-Encoding: gzip", "BODY payload",
			"POST /wire?q=1 HTTP/1.1", "Trailer: X-Trailer", "x-FIRST: a", "x-FIRST: b", "Cookie: a=1; b=2",
			"Host: wire.example.com", "Transfer-Encoding: chunked", "User-Agent: Go-http-client/1.1", "Z-Last: z", "Accept-Encoding: gzip", "BODY payload", "TRAILER X-Trailer: end",
		}
	}
	lines := []string{
		"GET /wire?q=1 HTTP/1.1", "x-FIRST: a", "x-FIRST: b", "Cookie: a=1; b=2",
		"Host: wire.example.com", "User-Agent: wire-test", "Z-Last: z", "Accept-Encoding: gzip",
	}
	return slices.Concat(lines, lines)
}

func wireHTTP2Frames(custom bool, firstStream int, requestBody bool) []string {
	const defaultHeaders = `":authority"="example.com" ":method"="GET" ":path"="/wire?q=1" ":scheme"="https" "cookie"="a=1" "cookie"="b=2" "user-agent"="wire-test" "x-first"="a" "x-first"="b" "z-last"="z" "accept-encoding"="gzip"`
	const customHeaders = `":method"="GET" ":authority"="example.com" ":scheme"="https" ":path"="/wire?q=1" "x-first"="a" "x-first"="b" "cookie"="a=1" "cookie"="b=2" "user-agent"="wire-test" "z-last"="z" "accept-encoding"="gzip"`
	if !custom {
		return []string{
			"SETTINGS 2=0 4=4194304 5=1048576 6=10485760",
			"WINDOW_UPDATE 0 1073741824",
			"HEADERS 1 end=true priority=false/0/false/0 " + defaultHeaders,
			"SETTINGS ACK",
			"HEADERS 3 end=true priority=false/0/false/0 " + defaultHeaders,
		}
	}
	initial := []string{
		"SETTINGS 1=65536 2=0 4=6291456 6=262144",
		"WINDOW_UPDATE 0 15663105",
		"SETTINGS ACK",
		"PRIORITY 3 0/false/15",
	}
	if requestBody {
		const postHeaders = `":method"="POST" ":authority"="example.com" ":scheme"="https" ":path"="/wire?q=1" "x-first"="a" "x-first"="b" "cookie"="a=1" "cookie"="b=2" "content-length"="7" "user-agent"="Go-http-client/2.0" "z-last"="z" "accept-encoding"="gzip"`
		return append(initial,
			fmt.Sprintf("HEADERS %d end=false priority=true/0/true/255 %s", firstStream, postHeaders),
			fmt.Sprintf("DATA %d end=true %q", firstStream, "payload"),
			"SETTINGS ACK",
			fmt.Sprintf("HEADERS %d end=false priority=true/0/true/255 %s", firstStream+2, postHeaders),
			fmt.Sprintf("DATA %d end=true %q", firstStream+2, "payload"),
		)
	}
	return append(initial,
		fmt.Sprintf("HEADERS %d end=true priority=true/0/true/255 %s", firstStream, customHeaders),
		"SETTINGS ACK",
		fmt.Sprintf("HEADERS %d end=true priority=true/0/true/255 %s", firstStream+2, customHeaders),
	)
}

func checkWireJA3(t *testing.T, got wireClientHello, alpn string, shuffled bool) {
	t.Helper()
	want := wireClientHello{
		RecordVersion: 769, Version: 771,
		Ciphers:      []uint16{2570, 4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53},
		Extensions:   []uint16{2570, 11, 16, 27, 18, 10, 23, 13, 35, 43, 5, 65037, 51764, 0, 17513, 51, 65281, 45, 2570},
		Groups:       []uint16{2570, 4588, 29, 23, 24},
		Versions:     []uint16{772, 771},
		KeyShares:    []uint16{29, 23},
		PointFormats: "00", ALPN: alpn, ServerName: "example.com",
	}
	if shuffled {
		got.Extensions = slices.Clone(got.Extensions)
		slices.Sort(got.Extensions)
		slices.Sort(want.Extensions)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("custom ClientHello = %+v, want %+v", got, want)
	}
}

func serveWireHTTP1(conn net.Conn) ([]string, error) {
	reader := bufio.NewReader(conn)
	var lines []string
	readLines := func(prefix string) error {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			if line == "\r\n" {
				return nil
			}
			lines = append(lines, prefix+strings.TrimSuffix(line, "\r\n"))
		}
	}
	for range 2 {
		start := len(lines)
		if err := readLines(""); err != nil {
			return nil, err
		}
		var length int64
		var chunked bool
		for _, line := range lines[start+1:] {
			name, value, _ := strings.Cut(line, ":")
			value = strings.TrimSpace(value)
			switch {
			case strings.EqualFold(name, "Content-Length"):
				n, err := strconv.ParseUint(value, 10, 63)
				if err != nil {
					return nil, err
				}
				length = int64(n)
			case strings.EqualFold(name, "Transfer-Encoding"):
				chunked = strings.EqualFold(value, "chunked")
			}
		}
		switch {
		case chunked:
			body, err := io.ReadAll(internal.NewChunkedReader(reader))
			if err != nil {
				return nil, err
			}
			lines = append(lines, "BODY "+string(body))
			if err := readLines("TRAILER "); err != nil {
				return nil, err
			}
		case length > 0:
			var body strings.Builder
			if _, err := io.CopyN(&body, reader, length); err != nil {
				return nil, err
			}
			lines = append(lines, "BODY "+body.String())
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 204 No Content\r\n\r\n"); err != nil {
			return nil, err
		}
	}
	return lines, nil
}

func serveWireHTTP2(conn net.Conn) ([]string, error) {
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	b := make([]byte, len(preface))
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != preface {
		return nil, fmt.Errorf("client preface %q: %v", b, err)
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	var frames []string
	var requests int
	var pending uint32
	for requests < 2 {
		f, err := fr.ReadFrame()
		if err != nil {
			return nil, err
		}
		var ended uint32
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				frames = append(frames, "SETTINGS ACK")
				if pending != 0 {
					if err := writeWireHTTP2Response(fr, pending); err != nil {
						return nil, err
					}
					pending = 0
				}
				break
			}
			var settings []string
			f.ForeachSetting(func(s http2.Setting) error {
				settings = append(settings, fmt.Sprintf("%d=%d", s.ID, s.Val))
				return nil
			})
			frames = append(frames, "SETTINGS "+strings.Join(settings, " "))
		case *http2.WindowUpdateFrame:
			frames = append(frames, fmt.Sprintf("WINDOW_UPDATE %d %d", f.StreamID, f.Increment))
		case *http2.PriorityFrame:
			p := f.HTTP2PriorityParam
			frames = append(frames, fmt.Sprintf("PRIORITY %d %d/%t/%d", f.Header().StreamID, p.StreamDep, p.Exclusive, p.Weight))
		case *http2.MetaHeadersFrame:
			fields := make([]string, 0, len(f.Fields))
			for _, field := range f.Fields {
				fields = append(fields, fmt.Sprintf("%q=%q", field.Name, field.Value))
			}
			p := f.Priority
			frames = append(frames, fmt.Sprintf("HEADERS %d end=%t priority=%t/%d/%t/%d %s", f.StreamID, f.StreamEnded(), f.HasPriority(), p.StreamDep, p.Exclusive, p.Weight, strings.Join(fields, " ")))
			if f.StreamEnded() {
				ended = f.StreamID
			}
		case *http2.DataFrame:
			frames = append(frames, fmt.Sprintf("DATA %d end=%t %q", f.StreamID, f.StreamEnded(), f.Data()))
			if f.StreamEnded() {
				ended = f.StreamID
			}
		default:
			return nil, fmt.Errorf("unexpected HTTP/2 frame %v", f.Header())
		}
		if ended == 0 {
			continue
		}
		requests++
		if requests == 1 {
			pending = ended
			if err := fr.WriteSettings(); err != nil {
				return nil, err
			}
			if err := fr.WriteSettingsAck(); err != nil {
				return nil, err
			}
		} else if err := writeWireHTTP2Response(fr, ended); err != nil {
			return nil, err
		}
	}
	return frames, nil
}

func writeWireHTTP2Response(fr *http2.Framer, stream uint32) error {
	var block bytes.Buffer
	if err := hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "204"}); err != nil {
		return err
	}
	return fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true})
}

type wireTLSConn struct {
	net.Conn
	capture bool
	hello   bytes.Buffer
}

func (c *wireTLSConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.capture {
		c.hello.Write(p[:n])
	}
	return n, err
}

type wireClientHello struct {
	RecordVersion, Version      uint16
	Ciphers, Extensions, Groups []uint16
	Versions, KeyShares         []uint16
	PointFormats, ALPN          string
	ServerName                  string
}

func parseWireClientHello(t *testing.T, raw []byte) wireClientHello {
	t.Helper()
	record := cryptobyte.String(raw)
	var got wireClientHello
	var recordType, messageType uint8
	var body, hello, random, ciphers, extensions cryptobyte.String
	if !record.ReadUint8(&recordType) || recordType != 22 || !record.ReadUint16(&got.RecordVersion) ||
		!record.ReadUint16LengthPrefixed(&body) || !body.ReadUint8(&messageType) || messageType != 1 ||
		!body.ReadUint24LengthPrefixed(&hello) || !hello.ReadUint16(&got.Version) || !hello.Skip(32) ||
		!hello.ReadUint8LengthPrefixed(&random) || !hello.ReadUint16LengthPrefixed(&ciphers) ||
		!hello.ReadUint8LengthPrefixed(&random) || !hello.ReadUint16LengthPrefixed(&extensions) {
		t.Fatal("invalid TLS ClientHello")
	}
	got.Ciphers = wireTLSIDs(t, ciphers)
	for !extensions.Empty() {
		var id uint16
		var data, list cryptobyte.String
		var ok = true
		if !extensions.ReadUint16(&id) || !extensions.ReadUint16LengthPrefixed(&data) {
			t.Fatal("invalid TLS extension")
		}
		got.Extensions = append(got.Extensions, normalizeWireGREASE(id))
		switch id {
		case 0:
			var kind uint8
			var name cryptobyte.String
			ok = data.ReadUint16LengthPrefixed(&list) && list.ReadUint8(&kind) && kind == 0 && list.ReadUint16LengthPrefixed(&name)
			got.ServerName = string(name)
		case 10:
			ok = data.ReadUint16LengthPrefixed(&list)
			got.Groups = wireTLSIDs(t, list)
		case 11:
			ok = data.ReadUint8LengthPrefixed(&list)
			got.PointFormats = hex.EncodeToString(list)
		case 16:
			ok = data.ReadUint16LengthPrefixed(&list)
			var protocols []string
			for ok && !list.Empty() {
				ok = list.ReadUint8LengthPrefixed(&data)
				protocols = append(protocols, string(data))
			}
			got.ALPN = strings.Join(protocols, ",")
		case 43:
			ok = data.ReadUint8LengthPrefixed(&list)
			got.Versions = wireTLSIDs(t, list)
		case 51:
			ok = data.ReadUint16LengthPrefixed(&list)
			for ok && !list.Empty() {
				ok = list.ReadUint16(&id) && list.ReadUint16LengthPrefixed(&data)
				got.KeyShares = append(got.KeyShares, normalizeWireGREASE(id))
			}
		}
		if !ok {
			t.Fatal("invalid TLS extension payload")
		}
	}
	return got
}

func wireTLSIDs(t *testing.T, data cryptobyte.String) []uint16 {
	t.Helper()
	var ids []uint16
	for !data.Empty() {
		var id uint16
		if !data.ReadUint16(&id) {
			t.Fatal("invalid TLS ID vector")
		}
		ids = append(ids, normalizeWireGREASE(id))
	}
	return ids
}

func normalizeWireGREASE(id uint16) uint16 {
	if id>>8 == id&0xff && id&0xf == 0xa {
		return 0x0a0a
	}
	return id
}
