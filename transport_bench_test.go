//go:build !nethttpomithttp2 && !nethttpomithttp2client

package http

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"sync/atomic"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/wangluozhe/chttp/internal/transportbenchserver"
)

func BenchmarkTransportHTTP1KeepAlive(b *testing.B) {
	benchmarkTransport(b, false, false)
}

func BenchmarkTransportHTTP1NoKeepAlive(b *testing.B) {
	benchmarkTransport(b, false, true)
}

func BenchmarkTransportTLSHTTP1KeepAlive(b *testing.B) {
	benchmarkTransport(b, true, false)
}

func BenchmarkTransportTLSHTTP1NoKeepAlive(b *testing.B) {
	benchmarkTransport(b, true, true)
}

func BenchmarkTransportHTTP2KeepAlive(b *testing.B) {
	benchmarkTransportHTTP2(b, false, false)
}

func BenchmarkTransportHTTP2NoKeepAlive(b *testing.B) {
	benchmarkTransportHTTP2(b, false, true)
}

func BenchmarkTransportHTTP2JA3KeepAlive(b *testing.B) {
	benchmarkTransportHTTP2(b, true, false)
}

func BenchmarkTransportHTTP2JA3NoKeepAlive(b *testing.B) {
	benchmarkTransportHTTP2(b, true, true)
}

func benchmarkTransportHTTP2(b *testing.B, useJA3, disableKeepAlives bool) {
	b.Helper()
	server, err := transportbenchserver.StartHTTP2()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := server.Close(); err != nil {
			b.Error(err)
		}
	})

	protocols := new(Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	transport := DefaultTransport.(*Transport).Clone()
	transport.Proxy = nil
	transport.Protocols = protocols
	transport.DisableKeepAlives = disableKeepAlives
	transport.TLSClientConfig = &utls.Config{
		RootCAs:    benchmarkRoots(b, server.CertificatePEM),
		ServerName: "example.com", // DNS name on the httptest certificate, for SNI.
	}
	if useJA3 {
		configureBenchmarkJA3(b, transport)
	}

	var dials atomic.Int64
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return dial(ctx, network, address)
	}
	b.Cleanup(transport.CloseIdleConnections)
	client := &Client{Transport: transport}

	benchmarkRequests(b, "HTTP/2.0", func() (string, int, io.ReadCloser, error) {
		request, err := NewRequest(MethodGet, server.URL, nil)
		if err != nil {
			return "", 0, nil, err
		}
		if useJA3 {
			request.Header[PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
		}
		response, err := client.Do(request)
		if err != nil {
			return "", 0, nil, err
		}
		return response.Proto, response.StatusCode, response.Body, nil
	})

	wantDials := int64(1) // benchmarkRequests makes one untimed warm-up request.
	if disableKeepAlives {
		wantDials += int64(b.N)
	}
	if got := dials.Load(); got != wantDials {
		b.Fatalf("made %d TCP dials, want %d", got, wantDials)
	}
}

func configureBenchmarkJA3(b testing.TB, transport *Transport) *HTTP2Transport {
	b.Helper()
	// Use the profile from examples/tlsextensions-test.go with a fixed extension order.
	transport.JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,11-16-27-18-10-23-13-35-43-5-65037-51764-0-17513-51-65281-45-41,4588-29-23-24,0"
	transport.TLSClientConfig.OmitEmptyPsk = true
	transport.TLSExtensions = &TLSExtensions{
		SupportedVersions: &utls.SupportedVersionsExtension{
			Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12},
		},
		KeyShareCurves: &utls.KeyShareExtension{
			KeyShares: []utls.KeyShare{{Group: utls.X25519}, {Group: utls.CurveP256}},
		},
	}

	h2, err := HTTP2ConfigureTransports(transport)
	if err != nil {
		b.Fatal(err)
	}
	const headerTableSize = 65536
	h2.MaxDecoderHeaderTableSize = headerTableSize
	h2.HTTP2Settings = &HTTP2Settings{
		Settings: []HTTP2Setting{
			{ID: HTTP2SettingHeaderTableSize, Val: headerTableSize},
			{ID: HTTP2SettingEnablePush, Val: 0},
			{ID: HTTP2SettingInitialWindowSize, Val: 6291456},
			{ID: HTTP2SettingMaxHeaderListSize, Val: 262144},
		},
		ConnectionFlow: 15663105,
		HeaderPriority: &HTTP2PriorityParam{Exclusive: true, Weight: 255},
	}
	return h2
}

func benchmarkTransport(b *testing.B, useTLS, disableKeepAlives bool) {
	b.Helper()
	server, err := transportbenchserver.New(useTLS)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(server.Close)

	protocols := new(Protocols)
	protocols.SetHTTP1(true)
	transport := DefaultTransport.(*Transport).Clone()
	transport.Proxy = nil
	transport.Protocols = protocols
	transport.DisableKeepAlives = disableKeepAlives
	if useTLS {
		transport.TLSClientConfig = &utls.Config{RootCAs: benchmarkRoots(b, server.CertificatePEM)}
	}
	b.Cleanup(transport.CloseIdleConnections)
	client := &Client{Transport: transport}

	benchmarkRequests(b, "HTTP/1.1", func() (string, int, io.ReadCloser, error) {
		request, err := NewRequest(MethodGet, server.URL, nil)
		if err != nil {
			return "", 0, nil, err
		}
		response, err := client.Do(request)
		if err != nil {
			return "", 0, nil, err
		}
		return response.Proto, response.StatusCode, response.Body, nil
	})
}

func benchmarkRequests(b *testing.B, wantProto string, doRequest func() (string, int, io.ReadCloser, error)) {
	b.Helper()

	request := func() {
		proto, statusCode, body, err := doRequest()
		if err != nil {
			b.Fatal(err)
		}
		if proto != wantProto || statusCode != StatusOK {
			_ = body.Close()
			b.Fatalf("got %s status %d, want %s status %d", proto, statusCode, wantProto, StatusOK)
		}
		_, readErr := io.Copy(io.Discard, body)
		closeErr := body.Close()
		if readErr != nil {
			b.Fatal(readErr)
		}
		if closeErr != nil {
			b.Fatal(closeErr)
		}
	}

	request()
	b.ReportAllocs()
	for b.Loop() {
		request()
	}
}

func benchmarkRoots(b *testing.B, certificatePEM []byte) *x509.CertPool {
	b.Helper()
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		b.Fatal("benchmark server returned an invalid certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		b.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return roots
}
