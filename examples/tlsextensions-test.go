package main

import (
	"fmt"
	utls "github.com/refraction-networking/utls"
	http "github.com/wangluozhe/chttp"
	"io"

	"strconv"
)

var settings = map[string]http.HTTP2SettingID{
	"HEADER_TABLE_SIZE":      http.HTTP2SettingHeaderTableSize,
	"ENABLE_PUSH":            http.HTTP2SettingEnablePush,
	"MAX_CONCURRENT_STREAMS": http.HTTP2SettingMaxConcurrentStreams,
	"INITIAL_WINDOW_SIZE":    http.HTTP2SettingInitialWindowSize,
	"MAX_FRAME_SIZE":         http.HTTP2SettingMaxFrameSize,
	"MAX_HEADER_LIST_SIZE":   http.HTTP2SettingMaxHeaderListSize,
}

type H2Settings struct {
	//HEADER_TABLE_SIZE
	//ENABLE_PUSH
	//MAX_CONCURRENT_STREAMS
	//INITIAL_WINDOW_SIZE
	//MAX_FRAME_SIZE
	//MAX_HEADER_LIST_SIZE
	Settings map[string]int `json:"Settings"`
	//HEADER_TABLE_SIZE
	//ENABLE_PUSH
	//MAX_CONCURRENT_STREAMS
	//INITIAL_WINDOW_SIZE
	//MAX_FRAME_SIZE
	//MAX_HEADER_LIST_SIZE
	SettingsOrder  []string                 `json:"SettingsOrder"`
	ConnectionFlow int                      `json:"ConnectionFlow"`
	HeaderPriority map[string]interface{}   `json:"HeaderPriority"`
	PriorityFrames []map[string]interface{} `json:"PriorityFrames"`
}

func ToHTTP2Settings(h2Settings *H2Settings) (http2Settings *http.HTTP2Settings) {
	http2Settings = &http.HTTP2Settings{
		Settings:       nil,
		ConnectionFlow: 0,
		HeaderPriority: &http.HTTP2PriorityParam{},
		PriorityFrames: nil,
	}
	if h2Settings.Settings != nil {
		if h2Settings.SettingsOrder != nil {
			for _, orderKey := range h2Settings.SettingsOrder {
				val := h2Settings.Settings[orderKey]
				if val != 0 || orderKey == "ENABLE_PUSH" {
					http2Settings.Settings = append(http2Settings.Settings, http.HTTP2Setting{
						ID:  settings[orderKey],
						Val: uint32(val),
					})
				}
			}
		} else {
			for id, val := range h2Settings.Settings {
				http2Settings.Settings = append(http2Settings.Settings, http.HTTP2Setting{
					ID:  settings[id],
					Val: uint32(val),
				})
			}
		}
	}
	if h2Settings.ConnectionFlow != 0 {
		http2Settings.ConnectionFlow = h2Settings.ConnectionFlow
	}
	if h2Settings.HeaderPriority != nil {
		var weight int
		var streamDep int
		w := h2Settings.HeaderPriority["weight"]
		switch w.(type) {
		case int:
			weight = w.(int)
		case float64:
			weight = int(w.(float64))
		}
		s := h2Settings.HeaderPriority["streamDep"]
		switch s.(type) {
		case int:
			streamDep = s.(int)
		case float64:
			streamDep = int(s.(float64))
		}
		var priorityParam *http.HTTP2PriorityParam
		if w == nil {
			priorityParam = &http.HTTP2PriorityParam{
				StreamDep: uint32(streamDep),
				Exclusive: h2Settings.HeaderPriority["exclusive"].(bool),
			}
		} else {
			priorityParam = &http.HTTP2PriorityParam{
				StreamDep: uint32(streamDep),
				Exclusive: h2Settings.HeaderPriority["exclusive"].(bool),
				Weight:    uint8(weight - 1),
			}
		}
		http2Settings.HeaderPriority = priorityParam
	}
	if h2Settings.PriorityFrames != nil {
		for _, frame := range h2Settings.PriorityFrames {
			var weight int
			var streamDep int
			var streamID int
			priorityParamSource := frame["priorityParam"].(map[string]interface{})
			w := priorityParamSource["weight"]
			switch w.(type) {
			case int:
				weight = w.(int)
			case float64:
				weight = int(w.(float64))
			}
			s := priorityParamSource["streamDep"]
			switch s.(type) {
			case int:
				streamDep = s.(int)
			case float64:
				streamDep = int(s.(float64))
			}
			sid := frame["streamID"]
			switch sid.(type) {
			case int:
				streamID = sid.(int)
			case float64:
				streamID = int(sid.(float64))
			}
			var priorityParam http.HTTP2PriorityParam
			if w == nil {
				priorityParam = http.HTTP2PriorityParam{
					StreamDep: uint32(streamDep),
					Exclusive: priorityParamSource["exclusive"].(bool),
				}
			} else {
				priorityParam = http.HTTP2PriorityParam{
					StreamDep: uint32(streamDep),
					Exclusive: priorityParamSource["exclusive"].(bool),
					Weight:    uint8(weight - 1),
				}
			}
			http2Settings.PriorityFrames = append(http2Settings.PriorityFrames, http.HTTP2PriorityFrame{
				HTTP2FrameHeader: http.HTTP2FrameHeader{
					StreamID: uint32(streamID),
				},
				HTTP2PriorityParam: priorityParam,
			})
		}
	}
	return http2Settings
}

var supportedSignatureAlgorithmsExtensions = map[string]utls.SignatureScheme{
	"PKCS1WithSHA256":                     utls.PKCS1WithSHA256,
	"PKCS1WithSHA384":                     utls.PKCS1WithSHA384,
	"PKCS1WithSHA512":                     utls.PKCS1WithSHA512,
	"PSSWithSHA256":                       utls.PSSWithSHA256,
	"PSSWithSHA384":                       utls.PSSWithSHA384,
	"PSSWithSHA512":                       utls.PSSWithSHA512,
	"ECDSAWithP256AndSHA256":              utls.ECDSAWithP256AndSHA256,
	"ECDSAWithP384AndSHA384":              utls.ECDSAWithP384AndSHA384,
	"ECDSAWithP521AndSHA512":              utls.ECDSAWithP521AndSHA512,
	"Ed25519":                             utls.Ed25519,
	"PKCS1WithSHA1":                       utls.PKCS1WithSHA1,
	"ECDSAWithSHA1":                       utls.ECDSAWithSHA1,
	"rsa_pkcs1_sha1":                      utls.SignatureScheme(0x0201),
	"Reserved for backward compatibility": utls.SignatureScheme(0x0202),
	"ecdsa_sha1":                          utls.SignatureScheme(0x0203),
	"rsa_pkcs1_sha256":                    utls.SignatureScheme(0x0401),
	"ecdsa_secp256r1_sha256":              utls.SignatureScheme(0x0403),
	"rsa_pkcs1_sha256_legacy":             utls.SignatureScheme(0x0420),
	"rsa_pkcs1_sha384":                    utls.SignatureScheme(0x0501),
	"ecdsa_secp384r1_sha384":              utls.SignatureScheme(0x0503),
	"rsa_pkcs1_sha384_legacy":             utls.SignatureScheme(0x0520),
	"rsa_pkcs1_sha512":                    utls.SignatureScheme(0x0601),
	"ecdsa_secp521r1_sha512":              utls.SignatureScheme(0x0603),
	"rsa_pkcs1_sha512_legacy":             utls.SignatureScheme(0x0620),
	"eccsi_sha256":                        utls.SignatureScheme(0x0704),
	"iso_ibs1":                            utls.SignatureScheme(0x0705),
	"iso_ibs2":                            utls.SignatureScheme(0x0706),
	"iso_chinese_ibs":                     utls.SignatureScheme(0x0707),
	"sm2sig_sm3":                          utls.SignatureScheme(0x0708),
	"gostr34102012_256a":                  utls.SignatureScheme(0x0709),
	"gostr34102012_256b":                  utls.SignatureScheme(0x070A),
	"gostr34102012_256c":                  utls.SignatureScheme(0x070B),
	"gostr34102012_256d":                  utls.SignatureScheme(0x070C),
	"gostr34102012_512a":                  utls.SignatureScheme(0x070D),
	"gostr34102012_512b":                  utls.SignatureScheme(0x070E),
	"gostr34102012_512c":                  utls.SignatureScheme(0x070F),
	"rsa_pss_rsae_sha256":                 utls.SignatureScheme(0x0804),
	"rsa_pss_rsae_sha384":                 utls.SignatureScheme(0x0805),
	"rsa_pss_rsae_sha512":                 utls.SignatureScheme(0x0806),
	"ed25519":                             utls.SignatureScheme(0x0807),
	"ed448":                               utls.SignatureScheme(0x0808),
	"rsa_pss_pss_sha256":                  utls.SignatureScheme(0x0809),
	"rsa_pss_pss_sha384":                  utls.SignatureScheme(0x080A),
	"rsa_pss_pss_sha512":                  utls.SignatureScheme(0x080B),
	"ecdsa_brainpoolP256r1tls13_sha256":   utls.SignatureScheme(0x081A),
	"ecdsa_brainpoolP384r1tls13_sha384":   utls.SignatureScheme(0x081B),
	"ecdsa_brainpoolP512r1tls13_sha512":   utls.SignatureScheme(0x081C),
}

var certCompressionAlgoExtensions = map[string]utls.CertCompressionAlgo{
	"zlib":   utls.CertCompressionZlib,
	"brotli": utls.CertCompressionBrotli,
	"zstd":   utls.CertCompressionZstd,
}

var supportedVersionsExtensions = map[string]uint16{
	"GREASE": utls.GREASE_PLACEHOLDER,
	"1.3":    utls.VersionTLS13,
	"1.2":    utls.VersionTLS12,
	"1.1":    utls.VersionTLS11,
	"1.0":    utls.VersionTLS10,
}

var pskKeyExchangeModesExtensions = map[string]uint8{
	"PskModeDHE":   utls.PskModeDHE,
	"PskModePlain": utls.PskModePlain,
}

var keyShareCurvesExtensions = map[string]utls.KeyShare{
	"GREASE": utls.KeyShare{Group: utls.CurveID(utls.GREASE_PLACEHOLDER), Data: []byte{0}},
	"P256":   utls.KeyShare{Group: utls.CurveP256},
	"P384":   utls.KeyShare{Group: utls.CurveP384},
	"P521":   utls.KeyShare{Group: utls.CurveP521},
	"X25519": utls.KeyShare{Group: utls.X25519},
}

type Extensions struct {
	//PKCS1WithSHA256 SignatureScheme = 0x0401
	//PKCS1WithSHA384 SignatureScheme = 0x0501
	//PKCS1WithSHA512 SignatureScheme = 0x0601
	//PSSWithSHA256 SignatureScheme = 0x0804
	//PSSWithSHA384 SignatureScheme = 0x0805
	//PSSWithSHA512 SignatureScheme = 0x0806
	//ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	//ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	//ECDSAWithP521AndSHA512 SignatureScheme = 0x0603
	//Ed25519 SignatureScheme = 0x0807
	//PKCS1WithSHA1 SignatureScheme = 0x0201
	//ECDSAWithSHA1 SignatureScheme = 0x0203
	SupportedSignatureAlgorithms []string `json:"SupportedSignatureAlgorithms"`
	//CertCompressionZlib   CertCompressionAlgo = 0x0001
	//CertCompressionBrotli CertCompressionAlgo = 0x0002
	//CertCompressionZstd   CertCompressionAlgo = 0x0003
	CertCompressionAlgo []string `json:"CertCompressionAlgo"`
	// Limit: 0x4001
	RecordSizeLimit int `json:"RecordSizeLimit"`
	//PKCS1WithSHA256 SignatureScheme = 0x0401
	//PKCS1WithSHA384 SignatureScheme = 0x0501
	//PKCS1WithSHA512 SignatureScheme = 0x0601
	//PSSWithSHA256 SignatureScheme = 0x0804
	//PSSWithSHA384 SignatureScheme = 0x0805
	//PSSWithSHA512 SignatureScheme = 0x0806
	//ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	//ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	//ECDSAWithP521AndSHA512 SignatureScheme = 0x0603
	//Ed25519 SignatureScheme = 0x0807
	//PKCS1WithSHA1 SignatureScheme = 0x0201
	//ECDSAWithSHA1 SignatureScheme = 0x0203
	DelegatedCredentials []string `json:"DelegatedCredentials"`
	//GREASE_PLACEHOLDER = 0x0a0a
	//VersionTLS10 = 0x0301
	//VersionTLS11 = 0x0302
	//VersionTLS12 = 0x0303
	//VersionTLS13 = 0x0304
	//VersionSSL30 = 0x0300
	SupportedVersions []string `json:"SupportedVersions"`
	//PskModePlain uint8 = pskModePlain
	//PskModeDHE   uint8 = pskModeDHE
	PSKKeyExchangeModes []string `json:"PSKKeyExchangeModes"`
	//PKCS1WithSHA256 SignatureScheme = 0x0401
	//PKCS1WithSHA384 SignatureScheme = 0x0501
	//PKCS1WithSHA512 SignatureScheme = 0x0601
	//PSSWithSHA256 SignatureScheme = 0x0804
	//PSSWithSHA384 SignatureScheme = 0x0805
	//PSSWithSHA512 SignatureScheme = 0x0806
	//ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	//ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	//ECDSAWithP521AndSHA512 SignatureScheme = 0x0603
	//Ed25519 SignatureScheme = 0x0807
	//PKCS1WithSHA1 SignatureScheme = 0x0201
	//ECDSAWithSHA1 SignatureScheme = 0x0203
	SignatureAlgorithmsCert []string `json:"SignatureAlgorithmsCert"`
	//GREASE_PLACEHOLDER = 0x0a0a
	//CurveP256 CurveID = 23
	//CurveP384 CurveID = 24
	//CurveP521 CurveID = 25
	//X25519    CurveID = 29
	KeyShareCurves []string `json:"KeyShareCurves"`
	//default is false, default is used grease, if not used grease the NotUsedGREASE param is true
	NotUsedGREASE bool `json:"NotUsedGREASE"`
}

func ToTLSExtensions(e *Extensions) (extensions *http.TLSExtensions) {
	extensions = &http.TLSExtensions{}
	if e == nil {
		return extensions
	}
	if e.SupportedSignatureAlgorithms != nil {
		extensions.SupportedSignatureAlgorithms = &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{}}
		for _, s := range e.SupportedSignatureAlgorithms {
			var signature_algorithms utls.SignatureScheme
			if val, ok := supportedSignatureAlgorithmsExtensions[s]; ok {
				signature_algorithms = val
			} else {
				hexInt, _ := strconv.ParseInt(s, 0, 0)
				signature_algorithms = utls.SignatureScheme(hexInt)
			}
			extensions.SupportedSignatureAlgorithms.SupportedSignatureAlgorithms = append(extensions.SupportedSignatureAlgorithms.SupportedSignatureAlgorithms, signature_algorithms)
		}
	}
	if e.CertCompressionAlgo != nil {
		extensions.CertCompressionAlgo = &utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{}}
		for _, s := range e.CertCompressionAlgo {
			extensions.CertCompressionAlgo.Algorithms = append(extensions.CertCompressionAlgo.Algorithms, certCompressionAlgoExtensions[s])
		}
	}
	if e.RecordSizeLimit != 0 {
		hexStr := fmt.Sprintf("0x%v", e.RecordSizeLimit)
		hexInt, _ := strconv.ParseInt(hexStr, 0, 0)
		extensions.RecordSizeLimit = &utls.FakeRecordSizeLimitExtension{uint16(hexInt)}
	}
	if e.DelegatedCredentials != nil {
		extensions.DelegatedCredentials = &utls.DelegatedCredentialsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{}}
		for _, s := range e.DelegatedCredentials {
			var signature_algorithms utls.SignatureScheme
			if val, ok := supportedSignatureAlgorithmsExtensions[s]; ok {
				signature_algorithms = val
			} else {
				hexStr := fmt.Sprintf("0x%v", e.RecordSizeLimit)
				hexInt, _ := strconv.ParseInt(hexStr, 0, 0)
				signature_algorithms = utls.SignatureScheme(hexInt)
			}
			extensions.DelegatedCredentials.SupportedSignatureAlgorithms = append(extensions.DelegatedCredentials.SupportedSignatureAlgorithms, signature_algorithms)
		}
	}
	if e.SupportedVersions != nil {
		extensions.SupportedVersions = &utls.SupportedVersionsExtension{Versions: []uint16{}}
		for _, s := range e.SupportedVersions {
			extensions.SupportedVersions.Versions = append(extensions.SupportedVersions.Versions, supportedVersionsExtensions[s])
		}
	}
	if e.PSKKeyExchangeModes != nil {
		extensions.PSKKeyExchangeModes = &utls.PSKKeyExchangeModesExtension{Modes: []uint8{}}
		for _, s := range e.PSKKeyExchangeModes {
			extensions.PSKKeyExchangeModes.Modes = append(extensions.PSKKeyExchangeModes.Modes, pskKeyExchangeModesExtensions[s])
		}
	}
	if e.SignatureAlgorithmsCert != nil {
		extensions.SignatureAlgorithmsCert = &utls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{}}
		for _, s := range e.SignatureAlgorithmsCert {
			var signature_algorithms_cert utls.SignatureScheme
			if val, ok := supportedSignatureAlgorithmsExtensions[s]; ok {
				signature_algorithms_cert = val
			} else {
				hexStr := fmt.Sprintf("0x%v", e.RecordSizeLimit)
				hexInt, _ := strconv.ParseInt(hexStr, 0, 0)
				signature_algorithms_cert = utls.SignatureScheme(hexInt)
			}
			extensions.SignatureAlgorithmsCert.SupportedSignatureAlgorithms = append(extensions.SignatureAlgorithmsCert.SupportedSignatureAlgorithms, signature_algorithms_cert)
		}
	}
	if e.KeyShareCurves != nil {
		extensions.KeyShareCurves = &utls.KeyShareExtension{KeyShares: []utls.KeyShare{}}
		for _, s := range e.KeyShareCurves {
			if val, ok := keyShareCurvesExtensions[s]; ok {
				extensions.KeyShareCurves.KeyShares = append(extensions.KeyShareCurves.KeyShares, val)
			} else {
				curveID, err := strconv.ParseInt(s, 10, 16)
				if err != nil {
					continue
				}
				extensions.KeyShareCurves.KeyShares = append(extensions.KeyShareCurves.KeyShares, utls.KeyShare{Group: utls.CurveID(curveID), Data: []byte{0}})
			}
		}
	}
	if e.NotUsedGREASE != false {
		extensions.NotUsedGREASE = e.NotUsedGREASE
	}
	return extensions
}

func main() {
	get()
}

func request(req *http.Request) {
	h2s := &H2Settings{
		Settings: map[string]int{
			"HEADER_TABLE_SIZE":    65536,
			"ENABLE_PUSH":          0,
			"INITIAL_WINDOW_SIZE":  6291456,
			"MAX_HEADER_LIST_SIZE": 262144,
			//"MAX_CONCURRENT_STREAMS": 1000,
			//"MAX_FRAME_SIZE":         16384,
		},
		SettingsOrder: []string{
			"HEADER_TABLE_SIZE",
			"ENABLE_PUSH",
			"INITIAL_WINDOW_SIZE",
			"MAX_HEADER_LIST_SIZE",
			//"MAX_CONCURRENT_STREAMS",
			//"MAX_FRAME_SIZE",
		},
		ConnectionFlow: 15663105,
		HeaderPriority: map[string]interface{}{
			"weight":    256,
			"streamDep": 0,
			"exclusive": true,
		},
	}
	h2ss := ToHTTP2Settings(h2s)
	tls := utls.Config{
		ClientSessionCache: utls.NewLRUClientSessionCache(0),
		OmitEmptyPsk:       true,
		//SessionTicketsDisabled: true, // Set to false when extension 41 exists
	}
	t1 := &http.Transport{
		TLSClientConfig:   &tls,
		DisableKeepAlives: false,
	}
	t2, err := http.HTTP2ConfigureTransports(t1)
	if err != nil {
		fmt.Println(err)
	}
	t2.HTTP2Settings = h2ss
	t1.H2Transport = t2
	t1.JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,11-16-27-18-10-23-13-35-43-5-65037-0-17513-51-65281-45-41,4588-29-23-24,0"
	t1.RandomJA3 = true
	es := &Extensions{
		SupportedSignatureAlgorithms: []string{
			"ECDSAWithP256AndSHA256",
			"ECDSAWithP384AndSHA384",
			"ECDSAWithP521AndSHA512",
			"PSSWithSHA256",
			"PSSWithSHA384",
			"PSSWithSHA512",
			"PKCS1WithSHA256",
			"PKCS1WithSHA384",
			"PKCS1WithSHA512",
			"ECDSAWithSHA1",
			"PKCS1WithSHA1",
		},
		//CertCompressionAlgo: []string{
		//	"brotli",
		//},
		RecordSizeLimit: 4001,
		DelegatedCredentials: []string{
			"ECDSAWithP256AndSHA256",
			"ECDSAWithP384AndSHA384",
			"ECDSAWithP521AndSHA512",
			"ECDSAWithSHA1",
		},
		SupportedVersions: []string{
			"1.3",
			"1.2",
		},
		PSKKeyExchangeModes: []string{
			"PskModeDHE",
		},
		KeyShareCurves: []string{
			"X25519",
			"P256",
		},
	}
	tes := ToTLSExtensions(es)
	t1.TLSExtensions = tes
	client := http.Client{Transport: t1}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	text, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(text))
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	text, err = io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(text))
}

func get() {
	rawurl := "https://tls.peet.ws/api/all"
	req, _ := http.NewRequest("GET", rawurl, nil)
	headers := http.Header{
		"User-Agent":                []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.60"},
		"accept":                    []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
		"accept-language":           []string{"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"},
		"accept-encoding":           []string{"gzip, deflate, br"},
		"upgrade-insecure-requests": []string{"1"},
		"sec-fetch-dest":            []string{"document"},
		"sec-fetch-mode":            []string{"navigate"},
		"sec-fetch-site":            []string{"none"},
		"sec-fetch-user":            []string{"?1"},
		"te":                        []string{"trailers"},
		http.PHeaderOrderKey: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		http.HeaderOrderKey: []string{
			"user-agent",
			"accept",
			"accept-language",
			"accept-encoding",
			"upgrade-insecure-requests",
			"sec-fetch-dest",
			"sec-fetch-mode",
			"sec-fetch-site",
			"sec-fetch-user",
			"te",
		},
	}
	req.Header = headers
	request(req)
}
