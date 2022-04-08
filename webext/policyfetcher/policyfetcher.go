package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/cyrill-k/fpki/common"
	"github.com/cyrill-k/fpki/dns/util"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

// MsgRes is a NativeMessage Response
type MsgRes struct {
	//
	Domain              string
	Valid               bool
	Error               string
	AllowHTTP           bool
	HasUniquePublicKey  bool
	UniquePublicKey     string
	TimeToRetrieveProof int64
	TimeToValidate      int64
}

// MsgReq is a NativeMessage Request
type MsgReq struct {
	Domain          string
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
	var inLen uint32
	err := binary.Read(b, order, &inLen)
	if err != nil {
		return err
	}

	input := make([]byte, inLen)
	_, err = io.ReadFull(b, input)
	if err != nil {
		return err
	}

	return json.Unmarshal(input, m)
}

func (m *MsgRes) Write(b io.Writer, order binary.ByteOrder) error {
	text, err := json.Marshal(*m)
	if err != nil {
		return err
	}

	textLen := new(bytes.Buffer)
	err = binary.Write(textLen, order, uint32(len(text)))
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(b, "%s%s", textLen, text)
	return err
}

func main() {
	order := binary.LittleEndian

	var err error

	reader := bufio.NewReader(os.Stdin)

	// for {
	var req MsgReq
	err = req.Read(reader, order)
	if err != nil {
		if err != io.EOF {
			fmt.Fprint(os.Stderr, "ReadError: ", err, "\n")
		}
		return
		// continue
	}

	start := time.Now()
	res := MsgRes{Domain: req.Domain}

	// Retrieve TXT record
	dnsRequestUrl := strings.TrimSuffix(req.Domain, ".") + "." + strings.TrimSuffix(req.MapserverDomain, ".") + "."
	proofBytes, err := common.RetrieveTxtRecord(dnsRequestUrl, req.ResolverAddress, req.Compressed)
	// fmt.Fprint(os.Stderr, "proof = ", proofBytes, "\n")
	if err != nil {
		writeResponse(res, fmt.Errorf("Retrieve txt error: %s", err), order)
		return
	}

	res.TimeToRetrieveProof = time.Now().Sub(start).Nanoseconds()

	start = time.Now()

	// var certificate []x509.Certificate
	// if len(req.Certificate) == 0 {
	// 	certificate = nil
	// } else {
	// 	certificate, err = common.X509ParseCertificates(req.Certificate)
	// 	if err != nil {
	// 		writeResponse(req.Domain, fmt.Errorf("Parsing certificate failed: %s", err), order)
	// 		return
	// 	}
	// }
	// fmt.Fprint(os.Stderr, "proof = ", req.Proof, "\n")

	// Read map ID
	dat, err := ioutil.ReadFile(req.MapID)
	if err != nil {
		writeResponse(res, fmt.Errorf("Error reading map ID: %s", err), order)
		return
	}
	mapIDString := strings.TrimSuffix(string(dat), "\n")
	mapID, err := strconv.Atoi(mapIDString)
	if err != nil {
		writeResponse(res, fmt.Errorf("Error parsing map ID: %s", err), order)
		return
	}

	// Parse trusted CAs
	var trustedCAs [][]byte
	for _, s := range req.TrustedCAs {
		h, err := hex.DecodeString(s)
		if err != nil {
			writeResponse(res, fmt.Errorf("Error parsing trusted CAs: %s", err), order)
			return
		}
		trustedCAs = append(trustedCAs, h)
	}

	// Verify map server proof
	policy, _, err := util.GetVerifiedPolicy(req.Domain, proofBytes, int64(mapID), req.MapPK, trustedCAs, req.Compressed)
	if err != nil {
		writeResponse(res, fmt.Errorf("Error verifying certificate: %s", err), order)
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

	writeResponse(res, nil, order)
}

func writeResponse(res MsgRes, err error, order binary.ByteOrder) {
	if err != nil {
		res.Error = err.Error()
	}
	res.Valid = err == nil
	err = res.Write(os.Stdout, order)
	if err != nil {
		fmt.Fprint(os.Stderr, "WriteError: ", err, "\n")
		// continue
	}

}
