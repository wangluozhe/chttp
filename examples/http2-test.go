package main

import (
	"fmt"
	"github.com/wangluozhe/chttp"
	"github.com/wangluozhe/chttp/http2"
	"io"
)

func main() {
	h2t := &http2.Transport{}
	client := http.Client{Transport: h2t}
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
