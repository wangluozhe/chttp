package main

import (
	"fmt"
	"github.com/wangluozhe/chttp"
	"io"
)

func main() {
	client := http.Client{Transport: &http.Transport{}}
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
