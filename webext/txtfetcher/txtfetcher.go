package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/cyrill-k/trustflex/common"
	"io"
	"os"
)

// MsgRes is a NativeMessage Response
type MsgRes struct {
	//
	Domain string
	Txt    []byte
}

// MsgReq is a NativeMessage Request
type MsgReq struct {
	Domain          string
	ResolverAddress string
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

	proofBytes, err := common.RetrieveTxtRecord(req.Domain, req.ResolverAddress, true)

	// fmt.Fprint(os.Stderr, "proof = ", proofBytes, "\n")
	if err != nil {
		fmt.Fprint(os.Stderr, "Retrieve txt error: ", err, "\n")
		return
	}
	res := MsgRes{req.Domain, proofBytes}
	err = res.Write(os.Stdout, order)
	if err != nil {
		fmt.Fprint(os.Stderr, "WriteError: ", err, "\n")
		return
		// continue
	}
	// }
}
