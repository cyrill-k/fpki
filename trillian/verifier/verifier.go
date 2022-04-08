package main

import (
	// "bufio"
	// "bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cyrill-k/fpki/common"
	"github.com/cyrill-k/fpki/dns/util"
)

// MsgRes is a NativeMessage Response
type MsgRes struct {
	//
	Domain                string
	Valid                 bool
	Error                 string
	AllowHTTP             bool
	HasUniquePublicKey    bool
	UniquePublicKey       string
	TimeToRetrieveProof   int64
	TimeToValidate        int64
	TotalTime             int64
	ProofSize             int64
	NCertificates         string
	NWildcardCertificates string
}

// MsgReq is a NativeMessage Request
type MsgReq struct {
	Domain          string
	Certificate     []byte
	MapserverDomain string
	ResolverAddress string
	Compressed      bool
	// path to file storing MapID
	MapID string
	// path to file storing MapPK
	MapPK      string
	TrustedCAs []string
}

func (m *MsgReq) Read(b io.Reader, order binary.ByteOrder) error {
	// var inLen uint32
	// err := binary.Read(b, order, &inLen)
	// if err != nil {
	// 	return err
	// }

	input, err := ioutil.ReadAll(b)
	if err != nil {
		return err
	} else {
		log.Printf("Read %d bytes: %s", len(input), string(input))
	}

	// input := make([]byte, 16000)
	// n, err := b.Read(input)
	// if err != nil && err != io.EOF {
	// 	return err
	// } else {
	// 	log.Printf("Read %d bytes: %s", n, string(input))
	// }

	return json.Unmarshal(input, m)
}

func (m *MsgRes) Write(b io.Writer, order binary.ByteOrder) error {
	text, err := json.Marshal(*m)
	if err != nil {
		return err
	}

	// textLen := new(bytes.Buffer)
	// err = binary.Write(textLen, order, uint32(len(text)))
	// if err != nil {
	// 	return err
	// }

	log.Printf("Write %d bytes: %s", len(text), text)
	_, err = fmt.Fprintf(b, "%s", text)
	return err
}

type handler struct {
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	order := binary.LittleEndian

	var err error

	fmt.Fprint(os.Stderr, "r.Method=", r.Method, ", r.URL=", r.URL, "\n")
	// reader := bufio.NewReader(os.Stdin)
	reader := r.Body

	// for {
	var req MsgReq
	err = req.Read(reader, order)
	if err != nil {
		if err != io.EOF {
			fmt.Fprint(os.Stderr, "ReadError: ", err, "\n")
		}
		log.Printf("err = %s", err)
		return
		// continue
	}

	incoming_http_request_time := time.Now()
	start := time.Now()
	res := MsgRes{Domain: req.Domain}

	// extract proof from the certificate extension if a certificate was specified and fetch proof
	// via DNS otherwise
	var proofBytes []byte
	if len(req.Certificate) == 0 {
		// Retrieve TXT record
		dnsRequestUrl := strings.TrimSuffix(req.Domain, ".") + "." + strings.TrimSuffix(req.MapserverDomain, ".") + "."
		proofBytes, err = common.RetrieveTxtRecord(dnsRequestUrl, req.ResolverAddress, req.Compressed)
		// fmt.Fprint(os.Stderr, "proof = ", proofBytes, "\n")
		if err != nil {
			writeResponse(w, res, fmt.Errorf("Retrieve txt error: %s", err), order)
			return
		}
	} else {
		var certificate []x509.Certificate
		if len(req.Certificate) == 0 {
			certificate = nil
		} else {
			certificate, err = common.X509ParseCertificates(req.Certificate)
			if err != nil {
				writeResponse(w, res, fmt.Errorf("Parsing certificate failed: %s", err), order)
				return
			}
		}

		cert_ext_found := false
		// 1.2.3.4.5.6.7.8.9 oid = []bytes{42, 3, 4, 5, 6, 7, 8, 9}
		proof_oid := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 9}
		for _, ext := range certificate[0].Extensions {
			log.Printf("%+v", ext.Id)
			isEqual := true
			if len(ext.Id) != len(proof_oid) {
				isEqual = false
				continue
			}
			for i, v := range ext.Id {
				if v != proof_oid[i] {
					isEqual = false
				}
			}
			if isEqual {
				proofBytes = ext.Value
				cert_ext_found = true
			}
			// if !isEqual {
			// 	continue
			// }
			// var ext_id []byte
			// // log.Printf("ext.Id = %+v -> %+v", ext.Id)
			// _, err := asn1.Unmarshal(ext_id, ext.Id)
			// if err != nil {
			// 	writeResponse(w, res, fmt.Errorf("Failed to unmarshal OID %+v", certificate[0].Extensions), order)
			// 	return
			// }
			// // 1.2.3.4.5.6.7.8.9 oid = []bytes{42, 3, 4, 5, 6, 7, 8, 9}
			// if bytes.Compare(ext_id, []byte{42, 3, 4, 5, 6, 7, 8, 9}) == 0 {
			// 	proofBytes = ext.Value
			// 	cert_ext_found = true
			// }
		}
		if !cert_ext_found {
			writeResponse(w, res, fmt.Errorf("Could not find proof extension in %+v", certificate[0].Extensions), order)
			return
		}
	}

	res.TimeToRetrieveProof = time.Now().Sub(start).Nanoseconds()

	res.ProofSize = int64(len(proofBytes))

	// var certificate []x509.Certificate
	// if len(req.Certificate) == 0 {
	// 	certificate = nil
	// } else {
	// 	certificate, err = common.X509ParseCertificates(req.Certificate)
	// 	if err != nil {
	// 		writeResponse(w, req.Domain, fmt.Errorf("Parsing certificate failed: %s", err), order)
	// 		return
	// 	}
	// }
	// fmt.Fprint(os.Stderr, "proof = ", req.Proof, "\n")

	// Read map ID
	dat, err := ioutil.ReadFile(req.MapID)
	if err != nil {
		writeResponse(w, res, fmt.Errorf("Error reading map ID: %s", err), order)
		return
	}
	mapIDString := strings.TrimSuffix(string(dat), "\n")
	mapID, err := strconv.Atoi(mapIDString)
	if err != nil {
		writeResponse(w, res, fmt.Errorf("Error parsing map ID: %s", err), order)
		return
	}

	// Parse trusted CAs
	var trustedCAs [][]byte
	for _, s := range req.TrustedCAs {
		h, err := hex.DecodeString(s)
		if err != nil {
			writeResponse(w, res, fmt.Errorf("Error parsing trusted CAs: %s", err), order)
			return
		}
		trustedCAs = append(trustedCAs, h)
	}

	start = time.Now()

	// Verify map server proof
	policy, proofDebugInfo, err := util.GetVerifiedPolicy(req.Domain, proofBytes, int64(mapID), req.MapPK, trustedCAs, req.Compressed)
	if err != nil {
		writeResponse(w, res, fmt.Errorf("Error verifying certificate: %s", err), order)
		return
	}

	res.AllowHTTP = false
	if val, ok := policy["_ALLOW_HTTP"]; ok {
		if val.(bool) {
			res.AllowHTTP = true
		}
	}

	res.HasUniquePublicKey = false
	if val, ok := policy["UNIQUE"]; ok {
		if val.(bool) {
			res.HasUniquePublicKey = true
		}
	}

	res.UniquePublicKey = ""
	if pk, ok := policy["UNIQUE_PK"]; ok {
		pkBytes := pk.([]byte)
		pkBase64 := base64.StdEncoding.EncodeToString(pkBytes)
		res.UniquePublicKey = pkBase64
	}

	res.TimeToValidate = time.Now().Sub(start).Nanoseconds()
	res.TotalTime = time.Now().Sub(incoming_http_request_time).Nanoseconds()

	ncerts := make([]string, len(proofDebugInfo.NCertificates))
	nwcerts := make([]string, len(proofDebugInfo.NWildcardCertificates))
	for i := 0; i < len(ncerts); i++ {
		ncerts[i] = strconv.FormatInt(proofDebugInfo.NCertificates[i], 10)
		nwcerts[i] = strconv.FormatInt(proofDebugInfo.NWildcardCertificates[i], 10)
	}
	res.NCertificates = strings.Join(ncerts, "_")
	res.NWildcardCertificates = strings.Join(nwcerts, "_")

	writeResponse(w, res, nil, order)
}

func main() {
	http.Handle("/", new(handler))
	log.Fatal(http.ListenAndServe(":8096", nil))
}

func writeResponse(writer io.Writer, res MsgRes, err error, order binary.ByteOrder) {
	if err != nil {
		res.Error = err.Error()
	}
	res.Valid = err == nil
	err = res.Write(writer, order)
	if err != nil {
		fmt.Fprint(os.Stderr, "WriteError: ", err, "\n")
		// continue
	} else {
		fmt.Fprint(os.Stderr, "Sent reply\n")
	}

}
