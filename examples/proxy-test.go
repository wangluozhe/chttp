package main

import (
	"fmt"
	"github.com/wangluozhe/chttp"
	"io"
	"net/url"
)

func main() {
	proxyURL, _ := url.Parse("http://127.0.0.1:7890")
	client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
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
