package main

import (
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/wangluozhe/chttp"
	"github.com/wangluozhe/chttp/httputil"
)

func main() {
	h1transport := &http.Transport{}
	h2transport, err := http.HTTP2ConfigureTransports(h1transport)
	h2transport.MaxDecoderHeaderTableSize = 65536
	h1transport.H2Transport = h2transport
	urls, _ := url.Parse("http://127.0.0.1:8888")
	h1transport.Proxy = http.ProxyURL(urls)
	client := http.Client{Transport: h1transport}
	req, err := http.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	req.ProtoMajor = 2
	req.Header = http.Header{
		http.PHeaderOrderKey: []string{":method", ":authority", ":scheme", ":path"},
		http.HeaderOrderKey:  []string{"accept", "accept-language", "cookie", "accept-encoding"},
		http.UnChangedHeaderKey: []string{
			"Accept",
			"Cookie",
			"Accept-Language",
		},
		"Accept":          []string{"*/*"},
		"Accept-Language": []string{"en-US,en;q=0.5"},
		"Accept-Encoding": []string{"gzip, deflate"},
		"Cookie":          []string{"Hm_lpvt_def79de877408c7bd826e49b694147bc=1648301329; Hm_lvt_def79de877408c7bd826e49b694147bc=\"1647245863,1647936048,1648296630\"; _ga=GA1.1.630251354.1645893020"},
		//"cookie": []string{"Hm_lpvt_def79de877408c7bd826e49b694147bc=1648301329", "Hm_lvt_def79de877408c7bd826e49b694147bc=\"1647245863,1647936048,1648296630\"", "_ga=GA1.1.630251354.1645893020"},
	}
	if err != nil {
		fmt.Println(err)
	}

	// 2. 打印原始 HTTP 请求报文 (Wire Format)
	dumpReq, _ := httputil.DumpRequestOut(req, true)
	fmt.Printf("%s [Wire] HTTP Raw Request:\n%s\n", time.Now().Format("2006/01/02 15:04:05"), string(dumpReq))

	response, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	_, err = io.ReadAll(response.Body)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println(string(text))
}
