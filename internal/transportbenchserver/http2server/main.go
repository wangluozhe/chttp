package main

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
)

type serverInfo struct {
	URL            string `json:"url"`
	CertificatePEM string `json:"certificate_pem"`
}

func main() {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	if err := json.NewEncoder(os.Stdout).Encode(serverInfo{
		URL:            server.URL,
		CertificatePEM: string(certificatePEM),
	}); err != nil {
		return
	}
	select {}
}
