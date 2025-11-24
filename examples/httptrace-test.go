package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/textproto"

	tls "github.com/refraction-networking/utls"
	"github.com/wangluozhe/chttp"
	"github.com/wangluozhe/chttp/httptrace"
)

func main() {
	//proxyURL, _ := url.Parse("http://127.0.0.1:7890")
	//client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	client := http.Client{}

	trace := &httptrace.ClientTrace{
		// 1. 连接获取阶段
		GetConn: func(hostPort string) {
			fmt.Printf("[Trace] GetConn: 准备获取连接 -> %s\n", hostPort)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			fmt.Printf("[Trace] GotConn: 成功获取连接 (Reused: %v, WasIdle: %v, IdleTime: %v)\n",
				info.Reused, info.WasIdle, info.IdleTime)
		},

		// 2. 连接放回/闲置阶段
		PutIdleConn: func(err error) {
			if err == nil {
				fmt.Println("[Trace] PutIdleConn: 连接已放回空闲池")
			} else {
				fmt.Printf("[Trace] PutIdleConn: 连接未能放回 (Err: %v)\n", err)
			}
		},

		// 3. DNS 解析阶段
		DNSStart: func(info httptrace.DNSStartInfo) {
			fmt.Printf("[Trace] DNSStart: 开始解析域名 -> %s\n", info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			fmt.Printf("[Trace] DNSDone: 域名解析完成 (Addrs: %v, Err: %v)\n", info.Addrs, info.Err)
		},

		// 4. TCP 连接阶段
		ConnectStart: func(network, addr string) {
			fmt.Printf("[Trace] ConnectStart: 开始建立 TCP 连接 -> %s %s\n", network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			fmt.Printf("[Trace] ConnectDone: TCP 连接完成 (Err: %v)\n", err)
		},

		// 5. TLS 握手阶段
		TLSHandshakeStart: func() {
			fmt.Println("[Trace] TLSHandshakeStart: 开始 TLS 握手")
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			// 注意：这里的 state 是 utls.ConnectionState
			fmt.Printf("[Trace] TLSHandshakeDone: TLS 握手完成 (CipherSuite: %d, ServerName: %s, Err: %v)\n",
				state.CipherSuite, state.ServerName, err)
		},

		// 6. 请求写入阶段
		WroteHeaderField: func(key string, value []string) {
			// 这个钩子调用非常频繁，生产环境建议注释掉
			//fmt.Printf("[Trace] WroteHeaderField: 写入头部 %s: %v\n", key, value)
		},
		WroteHeaders: func() {
			fmt.Println("[Trace] WroteHeaders: 所有请求头已写入")
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			fmt.Printf("[Trace] WroteRequest: 请求写入完成 (Err: %v)\n", info.Err)
		},

		// 7. 等待/响应阶段
		Wait100Continue: func() {
			fmt.Println("[Trace] Wait100Continue: 等待服务器 100 Continue 响应")
		},
		Got100Continue: func() {
			fmt.Println("[Trace] Got100Continue: 收到 100 Continue")
		},
		GotFirstResponseByte: func() {
			fmt.Println("[Trace] GotFirstResponseByte: 收到响应的第一个字节")
		},
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			fmt.Printf("[Trace] Got1xxResponse: 收到 1xx 响应 (Code: %d)\n", code)
			return nil
		},
	}

	//使用 chttp/httptrace 注入 Context
	ctx := httptrace.WithClientTrace(context.Background(), trace)

	//req, _ := http.NewRequest("GET", "https://www.google.com", nil)
	req, _ := http.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	text, _ := io.ReadAll(resp.Body)
	fmt.Println(string(text))
}
