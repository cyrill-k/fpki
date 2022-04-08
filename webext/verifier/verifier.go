package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
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
)

// MsgRes is a NativeMessage Response
type MsgRes struct {
	Domain string
	Valid  bool
	Error  string
}

// MsgReq is a NativeMessage Request
type MsgReq struct {
	Domain      string
	Proof       []byte
	Certificate []byte
	// path to file storing MapID
	MapID string
	// path to file storing MapPK
	MapPK      string
	TrustedCAs []string
	Compressed bool
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

	common.EnableDebug = true

	var err error

	reader := bufio.NewReader(os.Stdin)

	// for {
	var req MsgReq
	err = req.Read(reader, order)
	if err != nil {
		if err != io.EOF {
			writeResponse(req.Domain, fmt.Errorf("ReadError: %s", err), order)
			return
		}
		return
		// continue
	}

	var certificate []x509.Certificate
	if len(req.Certificate) == 0 {
		certificate = nil
	} else {
		certificate, err = common.X509ParseCertificates(req.Certificate)
		if err != nil {
			writeResponse(req.Domain, fmt.Errorf("Parsing certificate failed: %s", err), order)
			return
		}
	}
	// fmt.Fprint(os.Stderr, "proof = ", req.Proof, "\n")
	dat, err := ioutil.ReadFile(req.MapID)
	if err != nil {
		writeResponse(req.Domain, fmt.Errorf("Error reading map ID: %s", err), order)
		return
	}
	mapIDString := strings.TrimSuffix(string(dat), "\n")
	mapID, err := strconv.Atoi(mapIDString)
	if err != nil {
		writeResponse(req.Domain, fmt.Errorf("Error parsing map ID: %s", err), order)
		return
	}
	// fmt.Fprint(os.Stderr, "trustedCAs = ", req.TrustedCAs, "\n")
	var trustedCAs [][]byte
	for _, s := range req.TrustedCAs {
		h, err := hex.DecodeString(s)
		if err != nil {
			writeResponse(req.Domain, fmt.Errorf("Error parsing trusted CAs: %s", err), order)
			return
		}
		trustedCAs = append(trustedCAs, h)
	}
	// fmt.Fprint(os.Stderr, "mapID = ", mapID, "\n")
	// fmt.Fprint(os.Stderr, "mapPK = ", req.MapPK, "\n")
	err = util.VerifyFpki(req.Domain, req.Proof, certificate, int64(mapID), req.MapPK, trustedCAs, req.Compressed)
	if err != nil {
		fmt.Fprint(os.Stderr, "Error verifying certificate: ", err, "\n")
	}
	writeResponse(req.Domain, err, order)
}

func writeResponse(domain string, err error, order binary.ByteOrder) {
	var errorString string
	if err != nil {
		errorString = err.Error()
	}
	res := MsgRes{domain, err == nil, errorString}
	err = res.Write(os.Stdout, order)
	if err != nil {
		fmt.Fprint(os.Stderr, "WriteError: ", err, "\n")
		// continue
	}

}
