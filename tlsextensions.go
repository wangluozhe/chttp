package http

import (
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor"

	utls "github.com/refraction-networking/utls"
)

const (
	chrome  = "chrome"  //chrome User agent enum
	firefox = "firefox" //firefox User agent enum
)

type TLSExtensions struct {
	SupportedSignatureAlgorithms *utls.SignatureAlgorithmsExtension
	CertCompressionAlgo          *utls.UtlsCompressCertExtension
	RecordSizeLimit              *utls.FakeRecordSizeLimitExtension
	DelegatedCredentials         *utls.DelegatedCredentialsExtension
	SupportedVersions            *utls.SupportedVersionsExtension
	PSKKeyExchangeModes          *utls.PSKKeyExchangeModesExtension
	SignatureAlgorithmsCert      *utls.SignatureAlgorithmsCertExtension
	KeyShareCurves               *utls.KeyShareExtension
	TrustAnchors                 *utls.TrustAnchorsExtension
	NotUsedGREASE                bool

	// Deprecated: Use [Transport.ClientHelloHexStream] instead.
	ClientHelloHexStream string
}

type errExtensionNotExist struct {
	Context string
}

func (w *errExtensionNotExist) Error() string {
	return fmt.Sprintf("Extension {{ %s }} is not Supported by requests please raise an issue", w.Context)
}

func raiseExtensionError(info string) *errExtensionNotExist {
	return &errExtensionNotExist{
		Context: info,
	}
}

func parseUserAgent(userAgent string) string {
	userAgent = strings.ToLower(userAgent)
	switch {
	case strings.Contains(userAgent, "chrome"):
		return chrome
	case strings.Contains(userAgent, "applewebkit"):
		return chrome
	case strings.Contains(userAgent, "firefox"):
		return firefox
	default:
		return chrome
	}

}

func (t *Transport) tlsClient(conn net.Conn, cfg *utls.Config, onlyH1 bool) (*utls.UConn, error) {
	forceHTTP1 := onlyH1 || t.ForceHTTP1
	protocols := t.Protocols
	restrictALPN := protocols != nil && !(protocols.HTTP1() && protocols.HTTP2())
	hello := t.ClientHelloHexStream
	if extensions := t.TLSExtensions; extensions != nil && extensions.ClientHelloHexStream != "" {
		hello = extensions.ClientHelloHexStream
	}
	if hello == "" && t.ClientHelloID == nil && t.JA3 == "" {
		switch {
		case t.ForceHTTP1:
			cfg.NextProtos = []string{"http/1.1"}
		case restrictALPN && !onlyH1:
			cfg.NextProtos = slices.DeleteFunc(slices.Clone(cfg.NextProtos), func(p string) bool {
				return (p == "h2" && !protocols.HTTP2()) || (p == "http/1.1" && !protocols.HTTP1())
			})
		}
		return utls.UClient(conn, cfg, utls.HelloGolang), nil
	}

	var spec *utls.ClientHelloSpec
	switch {
	case hello != "":
		raw, err := hex.DecodeString(hello)
		if err != nil {
			return nil, fmt.Errorf("http: decoding ClientHello: %w", err)
		}
		f := utls.Fingerprinter{AllowBluntMimicry: true, RealPSKResumption: true}
		spec, err = f.FingerprintClientHello(raw)
		if err != nil {
			return nil, fmt.Errorf("http: parsing ClientHello: %w", err)
		}
		if !slices.ContainsFunc(spec.Extensions, func(ext utls.TLSExtension) bool {
			_, ok := ext.(utls.PreSharedKeyExtension)
			return ok
		}) {
			cfg.SessionTicketsDisabled = true
		}
	case t.ClientHelloID != nil:
		preset, err := utls.UTLSIdToSpec(*t.ClientHelloID)
		if err != nil {
			return nil, fmt.Errorf("http: selecting TLS ClientHello preset: %w", err)
		}
		spec = &preset
		cfg.PreferSkipResumptionOnNilExtension = true
		enabled := t.protocols()
		protocols = &enabled
		restrictALPN = !(enabled.HTTP1() && enabled.HTTP2())
	default:
		var extensions TLSExtensions
		if t.TLSExtensions != nil {
			extensions = *t.TLSExtensions
		}
		if extensions.KeyShareCurves != nil {
			keys := slices.Clone(extensions.KeyShareCurves.KeyShares)
			for i := range keys {
				g := keys[i].Group
				keys[i].Data = nil
				if g>>8 == g&0xff && g&0xf == 0xa {
					keys[i].Data = []byte{0}
				}
			}
			extensions.KeyShareCurves = &utls.KeyShareExtension{KeyShares: keys}
		}
		// ApplyPreset deep-clones the spec. The other extension fields can be read directly.
		var err error
		spec, err = extensions.StringToSpec(t.JA3, t.UserAgent, false, t.RandomJA3)
		if err != nil {
			return nil, err
		}
	}
	if forceHTTP1 || restrictALPN {
		selectALPN := func(next []string) []string {
			if forceHTTP1 {
				return []string{"http/1.1"}
			}
			return adjustNextProtos(next, *protocols)
		}
		spec.Extensions = slices.DeleteFunc(spec.Extensions, func(ext utls.TLSExtension) bool {
			alpn, ok := ext.(*utls.ALPNExtension)
			if !ok {
				return false
			}
			alpn.AlpnProtocols = selectALPN(alpn.AlpnProtocols)
			return len(alpn.AlpnProtocols) == 0
		})
		if len(cfg.EncryptedClientHelloConfigList) != 0 {
			// uTLS takes the encrypted inner ClientHello's ALPN from the config.
			cfg.NextProtos = selectALPN(cfg.NextProtos)
		}
	}
	tlsConn := utls.UClient(conn, cfg, utls.HelloCustom)
	if err := tlsConn.ApplyPreset(spec); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// StringToSpec creates a ClientHelloSpec based on a JA3 string
func (tlsExtensions *TLSExtensions) StringToSpec(ja3 string, userAgent string, forceHTTP1 bool, randomJA3 bool) (*utls.ClientHelloSpec, error) {
	tokens := strings.Split(ja3, ",")
	if len(tokens) != 5 {
		return nil, fmt.Errorf("http: invalid JA3: expected five fields")
	}
	if _, err := strconv.ParseUint(tokens[0], 10, 16); err != nil {
		return nil, err
	}
	if tlsExtensions == nil {
		tlsExtensions = &TLSExtensions{}
	}
	grease := parseUserAgent(userAgent) == chrome && !tlsExtensions.NotUsedGREASE
	var curves []utls.CurveID
	if grease {
		curves = append(curves, utls.GREASE_PLACEHOLDER)
	}
	if tokens[3] != "" {
		for curve := range strings.SplitSeq(tokens[3], "-") {
			id, err := strconv.ParseUint(curve, 10, 16)
			if err != nil {
				return nil, err
			}
			curves = append(curves, utls.CurveID(id))
		}
	}
	var pointFormats []byte
	if tokens[4] != "" {
		for point := range strings.SplitSeq(tokens[4], "-") {
			id, err := strconv.ParseUint(point, 10, 8)
			if err != nil {
				return nil, err
			}
			pointFormats = append(pointFormats, byte(id))
		}
	}

	extensionIDs := strings.Split(tokens[2], "-")
	exts := make([]utls.TLSExtension, 0, len(extensionIDs)+2)
	if grease {
		exts = append(exts, &utls.UtlsGREASEExtension{})
	}
	for _, id := range extensionIDs {
		ext := tlsExtensions.ja3Extension(id, curves, pointFormats, grease, forceHTTP1)
		if ext == nil {
			return nil, raiseExtensionError(id)
		}
		exts = append(exts, ext)
	}
	if grease {
		exts = append(exts, &utls.UtlsGREASEExtension{})
		// Keep a final padding or pre_shared_key extension last.
		if last := extensionIDs[len(extensionIDs)-1]; last == "21" || last == "41" {
			exts[len(exts)-2], exts[len(exts)-1] = exts[len(exts)-1], exts[len(exts)-2]
		}
	}

	suites := make([]uint16, 0, 2+strings.Count(tokens[1], "-"))
	if grease {
		suites = append(suites, utls.GREASE_PLACEHOLDER)
	}
	for c := range strings.SplitSeq(tokens[1], "-") {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		suites = append(suites, uint16(cid))
	}
	if randomJA3 {
		exts = utls.ShuffleChromeTLSExtensions(exts)
	}

	return &utls.ClientHelloSpec{
		CipherSuites:       suites,
		CompressionMethods: []byte{0},
		Extensions:         exts,
	}, nil
}

func (tlsExtensions *TLSExtensions) Clone() (*TLSExtensions, error) {
	data, err := cbor.Marshal(tlsExtensions, cbor.EncOptions{})
	if err != nil {
		return nil, err
	}

	var clone *TLSExtensions
	if err := cbor.Unmarshal(data, &clone); err != nil {
		return nil, err
	}
	return clone, nil
}

// chrome155TrustAnchorIDs returns the Chrome Root Store IDs advertised by a fresh
// Google Chrome 155.0.8059.40 (macOS) connection. Chrome encodes the IDs in
// lexicographic order. Return fresh slices because ClientHelloSpec is mutable.
// Source: https://chromium.googlesource.com/chromium/src/+/refs/tags/155.0.8059.40/net/data/ssl/chrome_root_store/root_store.textproto
func chrome155TrustAnchorIDs() [][]byte {
	return [][]byte{
		{0x82, 0xdf, 0x13, 0x02, 0x01},
		{0x82, 0xdf, 0x13, 0x02, 0x06},
		{0x82, 0xdf, 0x13, 0x02, 0x0d},
		{0x82, 0xdf, 0x13, 0x02, 0x0e},
		{0x82, 0xdf, 0x13, 0x02, 0x0f},
		{0x82, 0xdf, 0x13, 0x02, 0x12},
		{0x82, 0xdf, 0x13, 0x02, 0x13},
		{0x82, 0xdf, 0x13, 0x02, 0x14},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13},
		{0xd6, 0x79, 0x09, 0x01},
		{0xd6, 0x79, 0x09, 0x04},
		{0xd6, 0x79, 0x09, 0x05},
		{0xd6, 0x79, 0x09, 0x06},
		{0xd6, 0x79, 0x09, 0x07},
		{0xd6, 0x79, 0x09, 0x08},
		{0xd6, 0x79, 0x09, 0x0a},
		{0xd6, 0x79, 0x09, 0x0b},
		{0xd6, 0x79, 0x09, 0x0c},
		{0xd6, 0x79, 0x09, 0x0d},
		{0xd6, 0x79, 0x09, 0x0f},
	}
}

func (t *TLSExtensions) ja3Extension(id string, curves []utls.CurveID, points []byte, grease, forceHTTP1 bool) utls.TLSExtension {
	switch id {
	case "0":
		return &utls.SNIExtension{}
	case "5":
		return &utls.StatusRequestExtension{}
	case "10":
		return &utls.SupportedCurvesExtension{Curves: curves}
	case "11":
		return &utls.SupportedPointsExtension{SupportedPoints: points}
	case "13":
		if t.SupportedSignatureAlgorithms != nil {
			return t.SupportedSignatureAlgorithms
		}
		return &utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			},
		}
	case "16":
		if forceHTTP1 {
			return &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}}
		}
		return &utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
	case "17":
		return &utls.GenericExtension{Id: 17} // status_request_v2
	case "18":
		return &utls.SCTExtension{}
	case "21":
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}
	case "22":
		return &utls.GenericExtension{Id: 22} // encrypt_then_mac
	case "23":
		return &utls.ExtendedMasterSecretExtension{}
	case "24":
		return &utls.FakeTokenBindingExtension{}
	case "27":
		if t.CertCompressionAlgo != nil {
			return t.CertCompressionAlgo
		}
		return &utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{utls.CertCompressionBrotli}}
	case "28":
		if t.RecordSizeLimit != nil {
			return t.RecordSizeLimit
		}
		return &utls.FakeRecordSizeLimitExtension{Limit: 0x4001}
	case "34":
		if t.DelegatedCredentials != nil {
			return t.DelegatedCredentials
		}
		return &utls.DelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.ECDSAWithSHA1,
			},
		}
	case "35":
		return &utls.SessionTicketExtension{}
	case "41":
		return &utls.UtlsPreSharedKeyExtension{}
	case "43":
		if t.SupportedVersions != nil {
			return t.SupportedVersions
		}
		if grease {
			return &utls.SupportedVersionsExtension{Versions: []uint16{utls.GREASE_PLACEHOLDER, utls.VersionTLS13, utls.VersionTLS12}}
		}
		return &utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}}
	case "44":
		return &utls.CookieExtension{}
	case "45":
		if t.PSKKeyExchangeModes != nil {
			return t.PSKKeyExchangeModes
		}
		return &utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}}
	case "49":
		return &utls.GenericExtension{Id: 49} // post_handshake_auth
	case "50":
		if t.SignatureAlgorithmsCert != nil {
			return t.SignatureAlgorithmsCert
		}
		return &utls.SignatureAlgorithmsCertExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			},
		}
	case "51":
		if t.KeyShareCurves != nil {
			return t.KeyShareCurves
		}
		if grease {
			return &utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.GREASE_PLACEHOLDER, Data: []byte{0}},
				{Group: utls.X25519},
			}}
		}
		return &utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}, {Group: utls.CurveP256}}}
	case "57":
		return &utls.QUICTransportParametersExtension{}
	case "13172":
		return &utls.NPNExtension{}
	case "17513":
		return &utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}
	case "17613":
		return &utls.ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}}
	case "30032":
		return &utls.GenericExtension{Id: 30032, Data: []byte{0}}
	case "51764":
		if t.TrustAnchors != nil {
			return t.TrustAnchors
		}
		return &utls.TrustAnchorsExtension{TrustAnchorIDs: chrome155TrustAnchorIDs()}
	case "65037":
		return utls.BoringGREASEECH()
	case "65281":
		return &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}
	default:
		return nil
	}
}
