package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/wangluozhe/chttp"
	"github.com/wangluozhe/chttp/http2"
	"io"
)

var settings = map[string]http2.SettingID{
	"HEADER_TABLE_SIZE":      http2.SettingHeaderTableSize,
	"ENABLE_PUSH":            http2.SettingEnablePush,
	"MAX_CONCURRENT_STREAMS": http2.SettingMaxConcurrentStreams,
	"INITIAL_WINDOW_SIZE":    http2.SettingInitialWindowSize,
	"MAX_FRAME_SIZE":         http2.SettingMaxFrameSize,
	"MAX_HEADER_LIST_SIZE":   http2.SettingMaxHeaderListSize,
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

func ToHTTP2Settings(h2Settings *H2Settings) (http2Settings *http2.HTTP2Settings) {
	http2Settings = &http2.HTTP2Settings{
		Settings:       nil,
		ConnectionFlow: 0,
		HeaderPriority: &http2.PriorityParam{},
		PriorityFrames: nil,
	}
	if h2Settings.Settings != nil {
		if h2Settings.SettingsOrder != nil {
			for _, orderKey := range h2Settings.SettingsOrder {
				val := h2Settings.Settings[orderKey]
				if val != 0 || orderKey == "ENABLE_PUSH" {
					http2Settings.Settings = append(http2Settings.Settings, http2.Setting{
						ID:  settings[orderKey],
						Val: uint32(val),
					})
				}
			}
		} else {
			for id, val := range h2Settings.Settings {
				http2Settings.Settings = append(http2Settings.Settings, http2.Setting{
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
		var priorityParam *http2.PriorityParam
		if w == nil {
			priorityParam = &http2.PriorityParam{
				StreamDep: uint32(streamDep),
				Exclusive: h2Settings.HeaderPriority["exclusive"].(bool),
			}
		} else {
			priorityParam = &http2.PriorityParam{
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
			var priorityParam http2.PriorityParam
			if w == nil {
				priorityParam = http2.PriorityParam{
					StreamDep: uint32(streamDep),
					Exclusive: priorityParamSource["exclusive"].(bool),
				}
			} else {
				priorityParam = http2.PriorityParam{
					StreamDep: uint32(streamDep),
					Exclusive: priorityParamSource["exclusive"].(bool),
					Weight:    uint8(weight - 1),
				}
			}
			http2Settings.PriorityFrames = append(http2Settings.PriorityFrames, http2.PriorityFrame{
				FrameHeader: http2.FrameHeader{
					StreamID: uint32(streamID),
				},
				PriorityParam: priorityParam,
			})
		}
	}
	return http2Settings
}

func main() {
	post_akamai()
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
	client := http.Client{Transport: &http2.Transport{HTTP2Settings: h2ss}}
	resp, _ := client.Do(req)
	text, _ := io.ReadAll(resp.Body)
	fmt.Println(string(text))
}

func post_akamai() {
	rawurl := "https://wizzair.com/Pasa_uPN__WB7_Vm9KmP/3miXb0Nrkc/aDtvbS14Ag/aDoJIx/gyXXcB"
	json_data := map[string]interface{}{
		"sensor_data": "2;3160388;3290931;10,38,0,1,6,87;CY>z:6jA+qpFK1)N0,F4~25c)Z9(Q#U+1D3x9=)$N(?{^YRPIXAdu_=p?~VE_ye(q[,=!LYrhddPWFPmY@3%]c8IJ5`W?)U/;fVMu:taZQUATHP*g0`XQd1`/5qhH3rNn1&.Zw]EPK]R]UWB:_}#wFW{ac<aDE!f$7U3,[=$:/LG}6</2nRLOxE7fhSTL=%v<ghpOujUqt/8ST`_P|`^m<r_DN<B-5)tEm$(`C>%DFbv8<<L[%dQah1(mrm#nx_d5k*0L%VOfX&&{%Ex(Q@]-TN8;B6M>aPD~Vt) aU^&4`sz4#$|eNv,yOMH^Nr!4}eb#h0]F_c&8v7s%K5kR=5wELYE=e34LTV.~EhV>;enU7H 7G~2 w9TQ>@BooA9de{cQjA;|wX~B*T+H[FSKLo;-%$+Pf<Fey*{~Eqm]u5m<xO([7Uwef/<eKcv?Z(Dav0~5[8;/Vm(_>E$R7Mlv{L||#?Mw.u,X}@+&pJST{9 MC+dE|;vv|VJC<ayMdPoM^.-8fM]^&P>yqIOyn4noyd4PXr2w>xT.@jf{b!>1yHM/;v~ZCxRUlX5GR(R}ZAgTts[2TgY_Dma}E93(|J&neF7N,V#CB5/IG{/l`FtT`q8UZPOnenWng*BfuXLGtgjb60Vufgt?wc`MbLMHQ9s.[MDn$f:)pZG7|Ei#~zJmeEH2OHkQT:%U!s!Hd=Z{bOCA{]yMQDlB9!,{<6UI]L2k=09e-s[NB<b1fW NW^/3`AWWJMgpHF=4kALO$>){q%<z%{Jt`;pzmd XASu#4&/.I|O*a&FJpPuUh0joDa1W%S8Kfy;Meif?36M)niK[evrsvjIvF[>l!|AV*=aw?:N)i4?/Vq`la-&I76ycs9#aiu:^3>v:Z_xiIl4t[WOzrCEeQTA/L~aEY]|&1ZK>lw4~X>`C1DThk6H[cqSG}G;%?ArdG^:]4#]sTGmN@kEx+u5_m~YyaD*$N$m%d+]2N4/OE^2t>+W#9m/[d%vuIrtt3Y$_AxX.s5TYL4ipZ (SrSeHRjrhHve,%uX&uLCoc%GDV0msh/F.G~Gu6W`g={ui] hC=unC/[(8G.ayu?V>dEmRg6FJ.`w b5zdI;9~X8vu oLDtAZ@l8,G.h`{^O_vV2,cRNC.)R:N`QCPe1dQ)a;yN)4B3)MU>qrkXJQ>D O{? r9F(D:rnE09:2oaNY8VXi@PRYF+4Q5WD;a|i,+ZQ8~ZI_#uq=_T*:;D8B??d|xwtWl{e?[@;#{V}b$(_]}hSnm}z(-0.yDtJxNC#2?!GsAD?c/^83e5$47KP=vRv:@pw&QxnS-BIrH0sy|$/g?I,|XBI=Nb%XQ9ixS(|]jVr`waX1gl Y:;2G_08^l!,(fB^pL%pgx|)%5*}[0MdF!..Tu5De;ShR?p@=uvqj%z+6G;Jtj$E{m{ @d*6%vmsooNy,od^Wl!22]Of@,TmcDb[5X|G~=su7yi;MC+:<`b#7YP`I?h4.r]Fl&n7}3c#?=)E&hK>|;JV.-UsN,{!=8JkDkPuY3ks956c/}~4Bq|Jj$>ULAy%OLl+b-}VCeIc/06f81-S[,@}1q,C?AuHGKN7vW?MCw*{xsS3>s8UoLpJp@UCF*+fp$!}Xh`ei``PP*1m(4hcD*K((Zyy*]8K/Jn~2QqM=dw&}/=~Z|)Kr-#h0z=gg$v_u!Y-+obQY>#S2KgV8`oDRS}l9+N{1D-u&VyosNONO>AtUl2wf.E ;2t`8#M%9YW@ddoHA7<;I1.r_+I8)KcP nI@+rB:PjZZ$98t}l u)s-qbu`PMfEzYI!.dfA#Vmwi:mP6HHgQ|h*]J&3>P^j8s,[ucQ&a:^$rr%edfoq finjoq{tR2d6~AU+n8%4}_dhp9:rIq+PiG0$y[w<Ip;Ua2Bx<J.AcSLy^4mg?HDP+h*9$$2c3mGb.o:YPY/cH]:HAwk`YLtmZ_O#~qe$mb5[P;QJYa:ODyc|vE1oed:rD0ur>>Uz1M[Y/z6T6)KliQ~wkQt:ecVuH)`PT)uKEK}`BWsIJo|>NbM&G#UWfW?!$5wIBThdxfg)j6;t><?fzm*>g2H#-TO0sEPR4x.T57$Kw{(Ipt4F5Oi]Kq$)n%W2EVMx[Q.`,]s<]q/aGPgi7wqw27!zvB|L:Tbo6h:xY+w+P}[F?6SLc-|3?f|,I&np>wFND<yx>-Tj@eq$N&:3fjQ1!KxGB-F5N24nX2*<R03uV/y2Rzww(=4{ikt7:L$c86S8XI`hDFiNU5K5|L><?J6IS_@:kCoR<*iAsk0b_,v&S}1YYqH.8WzWtBk]1.{zmrv@2Wt|m5R*WS3~UK+Vv?-1WyjKZQVJTZdA1Y{#pG]EroII;!eFv02%X#yYqbq{-&@zp;m|s@sW9zkyg`?4Ju#&R.vdw!9;X^eJI$TX[6jR;.5+y{^Z.U`mDkhU|yF@kq(|&b,9DzR8/4.6~7&r@z-HxWcNkvCYl$88<|Xq(f>1q1}03;69r5RfN(4BQhBLt)}VP0)9U*hdgsf3&>;9|Jl-v]ji2Cb:J%TQaI/LlK6>5Jbqv,.<)dxB)|<Aj(PrKp8C_N>g}oMd9)#NQ{r1mi#LB-PV/N)[:U(8EC@_){d){9Q|2Oj{`IvHB;VhFvVr[5Ww.8AoE;a$I%2]l<+?:.`@5(1|++v:/O,AqEoyGzignf-,#$+Kmu?Y$UJnS)n#gvYr9EI0acg#9n]s2)H@;u~ef?>^},yJ}|8ebi!UBCJ]dgeo3cbSXT|2/;wO4khEH*tA!.Aofs MhAz^1l![bzaE[j<ukRW58 jC~>DC|7DuG)QNwe7eg Adz)g=>!1|%dc7|6eH=S6@cR*v*NvHavmn/G onRYPVPH%n)NJ;E&<))OI,|E9Qxqf~&BO#t~r&}~hPvC69Z*g2,v~VJ%f=OOP&B;~.w7>CMIB,`04-SxbD@9,khH>d7%QGZp8 (GPbYtc]<klpAuj<E-9,,mX$7/YVwrM$fTYn}6!3X64U.V;63.?,HdZ}V[1.70O^fWs&/PG2z8NOT//mxR4-2x%W5I[I%-wEN#2hr47E|k$Bn[YEldzj$~wT>Vta>DPs)]w[i/#C&x2K2l{u--Y[x`oO?R#gMip@OiUcR}n, w;_C&;,/^Z7Z@]:1Oopeyv2 Ut[tHRzcb.O<5GJg}UXn{?(!8agN|&^2m8x?(3M`(ZyuimI})`[6r=8#d60A-J[/oC/h7|ZX)N3yj7Oj*~f2>_CM&H`xS#a2nYBdE,`mb;Q`W 0i4g!]n95@$UT_5_>yjKBqe~P>u)69+an^wex`u8KS8z,:g2}d]@0pT+dq{JR5q6F,W?nMl:ZW<*BO-lL41{#fZ&cp&t]x c%e<xV4d2GYJ5No@t{VeZX%8QRv(qo5:kAzVQ1t<x$O:xdhb97q2ebFkZ7[$m__=xHBtuTDKQh3(&HgMC@6@yP!O4e>c_SuI,UN3/eeD.:fmm@ZK:<9JRa_aNLo6<3i<wNC6>&w[Jn>5KpB>#7*~Seiznj=dpnEkaH@7>4|ed#[UjBxxi x8Saw$SvM,<A{F6}*y0!0mh3s&4gGC@Ye*AYj.!)gCQ^3ss]knjFWH?y)%AlFWR`mM #1WzPF?7PD+amvj217PChOe~}uTf(Cm3%evqi(XptdAFA^^&*CCDfU]+5}7Ca*U_;DuHYF9[|kO]Yx~9OhhocR|=&z4Ap:y6Y<K)=#~GOc#_cv2UB61G20S+{t->t<&K*Z.6>8)^XD<.W|2[zE(o`K$b`Fl.li!U:oNb$m<!@8>I4.h#d/8Ub3qTu0WyT} ~}D%ZAO@|FB3C06(Qe913Z-^GN_#F5fUB,gRqGQT8{x!Ke>^AmHa#29uYrvP~g74~|Q6o@PnD1FAkoLt+L(Q~%:x_$D$UD_aruT?xM=`R+IM|J4[G$f2bp7xfv3qJ=*$nxnb3&/XC,]Q=dO%sM5f>WvUPh0hHJ6?:<87a[l<,&I_B[[C.ce;o1F>2T}jWFDKHZEY@&Hjhn5K&fW=5qvH,Mxy{?hQ8C@1RFkmFEo=A?l6|MG2.z~^8l<;<k29!5)NHbmtde3dYHGET@//9LxYZy}UhCDb.rBfp4cK?7Av(50:-wxD#stWM- skOb3TlsBNy%?ghwUgN}QU6D9KOaJ@~VE!]=*O?xIF}A-2Ci#|+l?jCGJU%1#&cJJWHrU[!3ZxXJmwq(JU{kD k||?DjYaN,IodCNd$J 4h,PWRb7~:zlt 28_f{%@pY.QC:DTzK V+H{0>::Xqpgos)G]pCDRD5W5|m3R+C#S,<p|r]FE|`OlrxP<9.-=5L9wy?k,e,o`n?w/[y5Q|fTzptTbj03>t5?k${CcF~YB+i7-2&.b7=9bzXdMp;FkhxZ!.7q2tOAu{W3O*%s#QUZ#K}F|>&:`jsY0&SfOKotQS*n9|!&}_ys9`GfV!c PZjC*R+nJU3@zyfT}So%}WmpRja(wM(R&5R:*<X:n_HD4>*yNB[xPO]zH n>jkRrUh3{d$?(nlMYIOCN$g%G>/NjE|^C7!bBv:MEKo:zFUFVMiYX~cu$li9I5[U=7tuN Sqxb4fP89ASVdTs@#ln;;V-vR9c;Ky_3#V`L8ix3RTSW]<=K?HSQV%R=zxuymgN2Z,@B}F!<4XwyzA]BI Sjh>jjRO7K=X0<[05L n`WmPOItzB@=~ZcqJ!~k}tyr&onA)5I/hml%7g!HU(w/SFXxR54w#oG+WMB.d(6|ptw2H(2s$OTVC,@`?Uu] G^`ri~b;d(sSmt<T(Cw7s{(sh)F5x{z?C_U4gD#l?cW6WU;S7L.Py3#</MqjSpk2FezEEW7)U(|h/>!; ]5^}FfYK^JB)FX{=Ou8Sj[Mv=@4^#V~d7$P*<qjnJqeZ|0ZwER+B]QS+YTV%S+SDyj;w9[Eq~ 1tJQ#> Hi)QNG+fiuHb|_BYBpX+XazO+;3^fDmQoIN;mH%[Rz(%oA>ymZOyBBCQjA?]!`2r? 7oq(o]n%UtuYZ1?mv@}&N5j&>c5iD-_DhzJhF2GMO]wj[UN8%@Ufuq[}%V&|JHq`#6p&xt,H>prSa^cNQ+o$,>/OnKpt>2vf?ibQH;_&cNWLS@XPQ?$>Om80N}UG: Qr!~Ie_g8VH+,,8>WON3%O-&!]wY+-~o[R:~BjojCffGY?vSDC9(!]},6i+rh]OHIB~lHryv4(_}0+CRkk*#xM)4<hH6#*k%p{]S9csoT.3*HHi}BKmad;r8BiI</8+B<F2:d87jF{+.KZ$0`pv>s{aj1fNP2DCZdo`b<(<R;*,{Fh0Np4U`jQ/5{W*:8HWlq!u|]Rc)t]mR?T&)*Jnu-#g3P/t*y@Ipp80>xr+WS=M[+I*P4Go%H4(DpsQg`+.Xh9:E,!JrsZz4d1sC{7y/H|IJC>q96g{FU$dDq0g!^1HZ4b;]CcDnaw~P2:+l>n2drfx27/Y2>:]fycO~)ETzAF:wSRSn1atSp?OU!!J1;Kq:kVGsq&-6!.0tR]_,<j/s9m#TbqB)47s;.e_/5p]*]jo^JJH}9[UdX?M.44 k /l10fhQD/vL4EV<*;9n;#N?bV{SPoeDZiP*#c`U`I,vJbtSdV.p+jI?|S$Z{8}n+u^fk]Y ]F@#i}Hp1C;h<92-h,f<Wt6cVI^kC`B9xtHVm[f1{K[nsrSwWK17,RztJ61i~i[ 7!8&s5ic];L<chGQ46fZ}ILKrNB,4sT5tomhc5[Ek2YM+7q|nhY:eyGM SZ;NNpv??I~MP[jbxr>KV9A7?}xJ(%6xLZ<`p4=cp{spY2GO&`n@0OcKhUZ `d-lC9pff84u`SHH%syExRKT80@?US)!U>M1HTB`%FE1):cfK?U{W70/POjfY}%`Lt,K`dxr_(#XG9>Un8!EYp$u5s_r4,5raWA<+wS#pC<KenL.Y#>2YrCH;~J(MM)Bc3^VNfvJ{Lxm,gn:&!D mWlvBO$4an)ch3d]-Ng%qhV}>@N&yyM uj+:W,q!M_VOoZy~|@FC3!RMigTB4a4q?;Qc4MmDP[v<BrUV],];",
	}
	data, _ := json.Marshal(json_data)
	payload := bytes.NewReader(data)
	req, _ := http.NewRequest("POST", rawurl, payload)
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
