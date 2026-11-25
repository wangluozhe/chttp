//go:build ignore

package main

import (
	"fmt"
	"github.com/wangluozhe/chttp"
	"io"
)

func main() {
	h1transport := &http.Transport{}
	h2transport, err := http.HTTP2ConfigureTransports(h1transport)
	h2transport.MaxDecoderHeaderTableSize = 65536
	h1transport.H2Transport = h2transport
	client := http.Client{Transport: h1transport}
	req, err := http.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	if err != nil {
		fmt.Println(err)
	}
	response, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	text, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(text))
}
