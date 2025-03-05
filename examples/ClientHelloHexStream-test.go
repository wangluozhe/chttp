package main

import (
	"fmt"
	utls "github.com/refraction-networking/utls"
	http "github.com/wangluozhe/chttp"
	"io"
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

func main() {
	get()
}

func request(req *http.Request) {
	h2s := &H2Settings{
		Settings: map[string]int{
			//"HEADER_TABLE_SIZE":    65536,
			"ENABLE_PUSH":         0,
			"INITIAL_WINDOW_SIZE": 2097152,
			//"MAX_HEADER_LIST_SIZE": 262144,
			"MAX_CONCURRENT_STREAMS": 100,
			//"MAX_FRAME_SIZE":         16384,
		},
		SettingsOrder: []string{
			//"HEADER_TABLE_SIZE",
			"ENABLE_PUSH",
			"INITIAL_WINDOW_SIZE",
			//"MAX_HEADER_LIST_SIZE",
			"MAX_CONCURRENT_STREAMS",
			//"MAX_FRAME_SIZE",
		},
		ConnectionFlow: 10485760,
		HeaderPriority: map[string]interface{}{
			"weight":    255,
			"streamDep": 0,
			"exclusive": false,
		},
	}
	h2ss := ToHTTP2Settings(h2s)
	tls := utls.Config{
		ClientSessionCache:     utls.NewLRUClientSessionCache(0),
		OmitEmptyPsk:           true,
		SessionTicketsDisabled: false, // Set to false when extension 41 exists
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
	t1.TLSExtensions = &http.TLSExtensions{}
	t1.TLSExtensions.ClientHelloHexStream = "16030107b4010007b00303297a9f99030f1f6f963cd97707ce6afcd9a0641d529687f8001812fb281e7f2e2024c5b25926bc62a04b7fab0289b1f9ef2e6e4657fcbd6f14333415c61f80e05b00202a2a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f003501000747aaaa000044cd00050003026832002d0002010100120000fe0d011a00000100011b00200ec8d22a5d2fa3db586816a6ef3b2a84a2fcdbc8dcbfe50f9e7636cc03143c2700f0949a7f091f6a068a9f336a799a51aa33b060ba067b0f536e1ef3cd9da2a65bed5f6134ff58d161e400da60cd5edc3c0d9c98fb2ae95cf7877c6578662ca1b4d6f56d556e57f8becce03bafedf738ad8509c08ebcfe982a12370607072b760feba3943c361aa78382c17cb5cb1fa1e35c9d8076584f1e37ec336fb8731430204c978046f790c3fbf5a3f50e1c40ad9fe83f1d13990b785e452d94208ea5bcc71feba2016b4b9aeae4086469ff349e7379511a3267d213dd78ede59086127dd52102ae89cb86224fbe126e5435991a11d13a926200a01fda1389908f500aea71c24b8226aa3aa53cecd61526ab5545a65e001b000302000200230000000500050100000000003304ef04ed1a1a00010011ec04c093f521c8c5beab3cc6db7a1b3df31da9e981bf795fe27b6497a3cb3ef23996ac77151c48128240697661a8d6adb6ea09dd06bb0760b5beab847ff4896f537dec36701eebc12de7bc9c155417321c07a31127e35aa5754b1eb2ca7285287c391d6077830113b0009c7904caaf66772d9e174d332315c99b38bb20115fdcc7e6a46d896b763789b2e693526ee7655982a845923192d31c36834046d0246cd5b43f30b73ed1833822cfd99c93066557ab8188f2d97e45b944bfac4686e0b01685674a0a3d3b324ad383ad5dd7137375a5c4940c0f7b40dfcca3f290ce2cd949a466c270035d926304bad804a1b5a756717252980b2473bcca5b58b0461268e435cf269d9da3a150d835f1784b975513c4d3c0159242bbc94ff1d76887f40eca86caabcc233db525cb441333d89788d599fa057af91b4c84b55496824dcb23bdcc007d68e71230548a51899eec62272a7592d22c0e3db6330b64ca1ea25b61981368124e1b210426e3c594d6c84a148cb27882ea028d9616afc0d35760dcbd13600ddb8505ed87bb8b8921c124491173457f414bd4849dbb8264a184970b4725f945c3538741c7931cf033190707ce755ccc0da03b03a3688d2b0686c595524866055c282200a119f358279240c3fc94ae34471135b8e7c37631d7cc7a83090d9c199a70050a1c7135697fed927581306a4c1995ad78c726f25155a15661354e816221b8d5b0daa39e822286fb959334d2718210a46d2b4e4890b6a402cfba182751e567e6ab8522c24b7776c2257c7f5af080c65780a4f2423197115af522648239f1e6b03349640bc25fbbdac1eb161748801b78599bc9dc1bbaf3825b93cd78d149541789982b77bb30b888e559ff7b4b5c8608bb237eee1a8d83acb016b49ce56c237f50621d46c421e207b0138a4db6acd1c07cc96c56e4b7a0d60ac08775601e77cdc206aa3f01026fdaa5ed288be274560c353617237b98c3c7f9d8121e494944739b766007563c45da407a15c7914aac07f0012dcd856c230c674c779c74b827e25b7b53305522a6425675b27345a7d2a5729cda108b645d83e4ced766071eb4486b7c40ae998f3c73473a684a75872b6c8848e6a72d26f3a1bdd74c0948b3a90928cdcc9082d954ae1c7d0a87778f975962b2a64c28ad2684157c65951b06badf94afab8081c266477a62831ab2492f06bd509aa8887b7aaa076ead23622e29a9d2f37c9c17a8a006a3ba436e57fb5ded499f68b866af1a4a21fa6e2eba85f65620ed2b80ca226a8ee018454345db03297a5980076783e185489627a54f46cd4fcb6e3415aca097a74581057fd01ebb3cc93c0552009b9c57103bd1a629920c801e48b71bf5cdaf86baa1b3c8cd00b307836b856cb335f33ca79c50ac638fa3cb7725e931e331a5d0883af3e9c12c0970f6bcabcd7a082ac739a8922a68a87f9d728c5b826a4ac707e554ce13da9e80dc76ee951dc56a7315d168776cc6a0708e00b35d93c9c1d5b35d294c7bb102949db48c2b96c2b4b86c8cbb2d936b323152a0d7444f0a6b26a32a494c1bb9f3524860292558175fb0563a8aba2f6c6082b05791dc2c39425ccb96544d9132a5a8fbb20617522a101adaeca52e5b5d11d1ecd01169d99005130fe2f25c92e3e183ebc1d55f0a7bce914384c023d64991770cd2f65a8bdac2c52c43b1f8825d8de970afc9869ebfe6a8691ce52d4668001d00200b91d21737c5d8bd0a06762d60b553de6736b46922beba78ce92061d09a50517ff010001000010000e000c02683208687474702f312e31002b000706baba03040303000a000c000a1a1a11ec001d0017001800000010000e00000b746c732e706565742e7773000d0012001004030804040105030805050108060601000b00020100001700008a8a0001000029009c0077007151e3c727aee70068f242743ab57930ddef7f86275e06bc109d5395b20a68259290130a7403d2622bac87a3511a5e55321cdc255324cd4bc0311faf8680776e0a1728799dba455b5eee62609b255a0310fe8586998862ed94f4e12ae1fd2e077be3e3d297230db983eabc33aa67d3ebad630294003a00212031ff9a0eec492f58af25fcf60ba41ccc4e2d6e961622e9c56b9f14bd10c9703e"
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
	t1.TLSExtensions.ClientHelloHexStream = "16030106dd010006d903033b04e05a876f646613392caa82b9ff3297fc8240ae37054c093a90a9972f052820204b9ab702de2e53635e9ab1b4bdced0fa87766c4911c1eadb5d0cc43080837b0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f003501000670aaaa0000002d0002010100120000000d001200100403080404010503080505010806060100170000000b00020100000500050100000000003304ef04ed5a5a00010011ec04c008c08839333d01c1024d7a9ff4f536728a64e27a0806779997058bf290a6667071df04164c253c73f427ff42c1fd64a0b362b37ebb3b2b0b4d6c263b9056239b73967f7543165c49c7f06f6d0706747b7592d28a691947193c3cc354212462b5d13787cd79a6c6bbcf58a15dcf2b97c4fc25fa919d945a6d9a2c25053467c8dbb3ffbb0c5420c8fda1519d007ab698345b329ae6f7bcfd19a6fe8ba404d6c4e9472bacc3b05c6c9695d5257ab26635d1113cb3aa3d47ba346786ec250f9a751355335719b02d71c1803eb58873172f0539bbf948439bd64625396dc254755d14b2f3b9b0692c1c9c9453854c59cf3a5028a720e90094ddbaca45f97a16c804c6e65c5b20150b61b63f652e9fe25bfd71770c7574580acf717c091b41ad562600d8771df29c9dda3963d326613f1a4995741d5fb45966f87b6bbbb585433eca14601a7756b2720c462ab5798ba79ba68d48a53665d007fb48039c8bb0b3d4a790583270386c6925a8dcf70c78b46c11cacb7a8006ab60016595a9e983466f160b5bd7770cf75e0c6a9de770ae7340c22080a238e1a286e116cf023efc222b37aa85ab2aa9a7326b65dc3ec9c472e6f4855896a16db253a4aa3cf28acf03939e80c40bfbb74cc593b8f332ba5a3b674bd262fad32f9e47381dfa25a6447a5db7af68cb33e12a27362a355c04338e8b05f3570cd5a7497b9039451607cec63ad82502dfbcc358320232e9b655c44c500399c978c2a02295aceb888ab314dee813694644bb0055343302dae37d68050432c4be6b68a5810a8c2653af3b0481b24cb120896ccfea308ca7148829954c05a17bb089ebdb0f6f7a9ebeeb59b356aa7cf67b7e979be9979ff7651dd02aa3c197151de1208126ae8a2128b78422bfb6cdb4167ebd1bc4886382a01b26c7c594283b8fb7f13a7d3a885fd224e6c1bc333640d12c889f06a1a7fa97fb3788f618b9a54155e0d32a8adc70b1d735b6d16b940c269d9658ae2a7d6a0ace6fbb0e9c858d01398b00c9bb17c467e7b0458faa68bc393ced41748ff31393c67034cab0081759bdeabc7109c54f1304f861790cd356fbe736e6d8a9fc3a9197a0ae432a5caa758eb172b04d0aafc70717aeeb9401b6054808b31ec08c6458852939a8e8934b7a737e94951138862e2ef10e1aaa6d4d37c8b4a24a410a118872762ff65fddea748f104296eb684afb71049abb7e446451426274f0b225262562e83ca017bcb9253b55b788a19910650553fba8c72b45681f2b48e7a3760b768e1ac6af744835abd89aa0daaa67b967dc2a4ad09bb7e0665ac3c09ee913bad3474600886f2c57b485aba1d1f1beaae0481b43aef5708f73303d5cc74c64840abf02076c941dd2a3bb0c032d437a39af30392b6960c725bc02dc6fab4bb34093bb60f4c4c938c569ac32c1f999b22bb1cbc011485052e8223c510072621c479d223d2f80478fa7b8a035160da59743c4388032bc1d034bfbe1c30341cde4e34716642827d324e679595b77584cb44cc5f63d9e75ad4248c43e1b8028dcb62892cc39d5911f79584dd44a702b0a01ac5354255931a247eb64776711537eccc515a8707600b4c4a6205cd7be0fa465bb544fc4d5311f388c13617ad020ec018647f5221e3859e42c62e6e44861d35d3a98b26fff41518ea72b35eb149b9d1dd949b2534878a43ea44d705613db0a134c8e8413afb0b5ee6d001d0020aef4c771ee42725795e801186d7d71311f37ebffef3a34ae35cb903cfe579109ff01000100002b0007062a2a0304030344cd00050003026832001b0003020002000a000c000a5a5a11ec001d00170018000000190017000014746c732e62726f777365726c65616b732e636f6d00230000fe0d00da00000100011700205c699d74083b4f205fb01affa7f910dfdc6ef6e7ee8385aeeb0e8a9f1da0142700b001f3f44ca4e2ed9fc7cfc2cf6832c3cdca48fa4cfaa9a04c871195d50fabf4c9b0d0ac66e8dc5e905a572d237ad89c82dd3cd434d7ddc555fda11ba322da55bdfc4551d6530a6a46ed3bb4340b134fff671089f2b90874acaef69eda9d4d4edf0fa45acc0de462c3432854339e141813a8c68415004f0809c55b4ed60da8a3ddd10283454bf5cc587f0a14a880cdaa9ef8b549a2521d5815b9521202746a57e37d4d8a66302db40172418cbe9a7219e60010000e000c02683208687474702f312e31baba000100"
	client = http.Client{Transport: t1}
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
		"User-Agent":      []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"},
		"accept":          []string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		"accept-language": []string{"zh-CN,zh-Hans;q=0.9"},
		//"accept-encoding": []string{"gzip, deflate, br"},
		"sec-fetch-dest": []string{"document"},
		"sec-fetch-mode": []string{"navigate"},
		"sec-fetch-site": []string{"none"},
		http.PHeaderOrderKey: []string{
			":method",
			":scheme",
			":path",
			":authority",
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
