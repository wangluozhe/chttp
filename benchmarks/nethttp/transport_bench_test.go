package nethttpbench

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	stdhttp "net/http"
	"sync/atomic"
	"testing"

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
	benchmarkTransportHTTP2(b, false)
}

func BenchmarkTransportHTTP2NoKeepAlive(b *testing.B) {
	benchmarkTransportHTTP2(b, true)
}

func benchmarkTransportHTTP2(b *testing.B, disableKeepAlives bool) {
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

	protocols := new(stdhttp.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	transport := stdhttp.DefaultTransport.(*stdhttp.Transport).Clone()
	transport.Proxy = nil
	transport.Protocols = protocols
	transport.DisableKeepAlives = disableKeepAlives
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    benchmarkRoots(b, server.CertificatePEM),
		ServerName: "example.com", // DNS name on the httptest certificate, for SNI.
	}

	var dials atomic.Int64
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return dial(ctx, network, address)
	}
	b.Cleanup(transport.CloseIdleConnections)
	client := &stdhttp.Client{Transport: transport}

	benchmarkRequests(b, "HTTP/2.0", func() (string, int, io.ReadCloser, error) {
		request, err := stdhttp.NewRequest(stdhttp.MethodGet, server.URL, nil)
		if err != nil {
			return "", 0, nil, err
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

func benchmarkTransport(b *testing.B, useTLS, disableKeepAlives bool) {
	b.Helper()
	server, err := transportbenchserver.New(useTLS)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(server.Close)

	protocols := new(stdhttp.Protocols)
	protocols.SetHTTP1(true)
	transport := stdhttp.DefaultTransport.(*stdhttp.Transport).Clone()
	transport.Proxy = nil
	transport.Protocols = protocols
	transport.DisableKeepAlives = disableKeepAlives
	if useTLS {
		transport.TLSClientConfig = &tls.Config{RootCAs: benchmarkRoots(b, server.CertificatePEM)}
	}
	b.Cleanup(transport.CloseIdleConnections)
	client := &stdhttp.Client{Transport: transport}

	benchmarkRequests(b, "HTTP/1.1", func() (string, int, io.ReadCloser, error) {
		request, err := stdhttp.NewRequest(stdhttp.MethodGet, server.URL, nil)
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
		if proto != wantProto || statusCode != stdhttp.StatusOK {
			_ = body.Close()
			b.Fatalf("got %s status %d, want %s status %d", proto, statusCode, wantProto, stdhttp.StatusOK)
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
