// Package transportbenchserver provides a small local HTTP/1.1 server for
// transport benchmarks. It avoids importing net/http so the chttp and standard
// library clients can be benchmarked in separate test binaries against the
// same server implementation.
package transportbenchserver

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HTTP2Server is an HTTP/2 test server running in a separate process.
// Separating it allows the standard net/http server to be shared by benchmark
// binaries that cannot link net/http and chttp into the same process.
type HTTP2Server struct {
	URL            string
	CertificatePEM []byte

	command   *exec.Cmd
	tempDir   string
	closeOnce sync.Once
	closeErr  error
}

// StartHTTP2 starts a standard library HTTP/2 server in a child process.
func StartHTTP2() (*HTTP2Server, error) {
	root, err := findModuleRoot()
	if err != nil {
		return nil, err
	}
	tempDir, err := os.MkdirTemp("", "chttp-transport-benchmark-")
	if err != nil {
		return nil, err
	}
	binary := filepath.Join(tempDir, "server")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "./internal/transportbenchserver/http2server")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("build HTTP/2 benchmark server: %w\n%s", err, output)
	}

	command := exec.Command(binary)
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	server := &HTTP2Server{command: command, tempDir: tempDir}
	line, err := bufio.NewReader(stdout).ReadBytes('\n')
	if err != nil {
		_ = server.Close()
		return nil, fmt.Errorf("start HTTP/2 benchmark server: %w\n%s", err, stderr.String())
	}
	var info struct {
		URL            string `json:"url"`
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(line, &info); err != nil {
		_ = server.Close()
		return nil, fmt.Errorf("decode HTTP/2 benchmark server info: %w", err)
	}
	server.URL = info.URL
	server.CertificatePEM = []byte(info.CertificatePEM)
	return server, nil
}

// Close stops the HTTP/2 server process and removes its temporary executable.
func (s *HTTP2Server) Close() error {
	s.closeOnce.Do(func() {
		if s.command != nil && s.command.Process != nil {
			if err := s.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				s.closeErr = err
			}
			if err := s.command.Wait(); err != nil {
				if exitErr, ok := err.(*exec.ExitError); !ok || !exitErr.Exited() {
					s.closeErr = err
				}
			}
		}
		if err := os.RemoveAll(s.tempDir); err != nil && s.closeErr == nil {
			s.closeErr = err
		}
	})
	return s.closeErr
}

func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not find go.mod from current directory")
		}
		dir = parent
	}
}

// Server serves a small fixed HTTP response over HTTP/1.1.
type Server struct {
	URL            string
	CertificatePEM []byte
	listener       net.Listener
	tlsConfig      *tls.Config

	closed     atomic.Bool
	closeOnce  sync.Once
	connMu     sync.Mutex
	conns      map[net.Conn]struct{}
	serveWG    sync.WaitGroup
	acceptDone chan struct{}
}

// New starts a local HTTP/1.1 server. When useTLS is true, it uses a
// self-signed certificate and negotiates only HTTP/1.1 with ALPN.
func New(useTLS bool) (*Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	server := &Server{
		listener:   listener,
		conns:      make(map[net.Conn]struct{}),
		acceptDone: make(chan struct{}),
	}
	if useTLS {
		certificate, certificatePEM, err := testCertificate()
		if err != nil {
			_ = listener.Close()
			return nil, err
		}
		server.CertificatePEM = certificatePEM
		server.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{"http/1.1"},
		}
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	server.URL = fmt.Sprintf("%s://%s", scheme, listener.Addr())
	go server.acceptLoop()
	return server, nil
}

// Close shuts down the listener and all active connections.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		_ = s.listener.Close()
		<-s.acceptDone

		s.connMu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.connMu.Unlock()
		s.serveWG.Wait()
	})
}

func (s *Server) acceptLoop() {
	defer close(s.acceptDone)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		if s.closed.Load() {
			_ = conn.Close()
			continue
		}

		s.connMu.Lock()
		if s.closed.Load() {
			s.connMu.Unlock()
			_ = conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.serveWG.Add(1)
		s.connMu.Unlock()
		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer s.serveWG.Done()
	acceptedConn := conn
	defer func() {
		s.connMu.Lock()
		delete(s.conns, acceptedConn)
		s.connMu.Unlock()
		_ = conn.Close()
	}()

	if s.tlsConfig != nil {
		tlsConn := tls.Server(conn, s.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		conn = tlsConn
	}
	reader := bufio.NewReader(conn)
	for {
		requestLine, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if len(requestLine) < 2 || requestLine[len(requestLine)-2:] != "\r\n" {
			return
		}

		closeAfterResponse := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
			if len(line) < 2 || line[len(line)-2:] != "\r\n" {
				return
			}
			if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(name, "Connection") && strings.EqualFold(strings.TrimSpace(value), "close") {
				closeAfterResponse = true
			}
		}

		connectionHeader := "Connection: keep-alive\r\n"
		if closeAfterResponse {
			connectionHeader = "Connection: close\r\n"
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n"+connectionHeader+"\r\nok"); err != nil {
			return
		}
		if closeAfterResponse {
			return
		}
	}
}

func testCertificate() (tls.Certificate, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return certificate, certificatePEM, nil
}
