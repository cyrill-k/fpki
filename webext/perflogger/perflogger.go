package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/cyrill-k/trustflex/common"
)

// MsgRes is a NativeMessage Response
type MsgRes struct {
	Domain string
	Logged bool
	Error  string
}

// MsgReq is a NativeMessage Request
type MsgReq struct {
	Id                       int
	Domain                   string
	TimeToHeadersReceived    int
	TimeToValidationFinished int
	TimeToRetrieveProof      int
	TimeToValidate           int
	TotalTime                int
	ProofSize                int
	NCertificates            string
	NWildcardCertificates    string
	Blocked                  bool
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
			writeResponse(req.Domain, fmt.Errorf("ReadError: %s", err), order)
			return
		}
		return
		// continue
	}

	f, err := common.OpenOrCreate("/home/cyrill/go/src/github.com/cyrill-k/trustflex/tls/e2e.csv")
	common.LogError("Can't open perf log file: %s", err)
	w := bufio.NewWriter(f)
	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()
	var blockedString string
	if req.Blocked {
		blockedString = "1"
	} else {
		blockedString = "0"
	}

	// log.Printf("Received packet: %+v", req)
	err = csvWriter.Write([]string{fmt.Sprintf("%d", req.Id), req.Domain, fmt.Sprintf("%d", req.TimeToHeadersReceived), fmt.Sprintf("%d", req.TimeToValidationFinished), fmt.Sprintf("%d", req.TimeToRetrieveProof), fmt.Sprintf("%d", req.TimeToValidate), fmt.Sprintf("%d", req.TotalTime), fmt.Sprintf("%d", req.ProofSize), req.NCertificates, req.NWildcardCertificates, blockedString})
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
