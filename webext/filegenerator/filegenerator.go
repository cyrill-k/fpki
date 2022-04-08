package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/cyrill-k/trustflex/common"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

// MsgRes is a NativeMessage Response
type MsgRes struct {
	Rank   int
	Domain string
}

// MsgReq is a NativeMessage Request
type MsgReq struct {
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

func readExperimentIdx() int64 {
	var lastIdx int64
	lastIdx = 0
	file, err := os.Open("/home/cyrill/go/src/github.com/cyrill-k/trustflex/tls/experimentIdx")
	if err == nil {
		// common.LogError("Failed to open lastIdx file: %s", err)
		defer file.Close()

		_, _ = fmt.Fscanf(file, "%d", &lastIdx)
		// common.LogError("Failed reading lastIdx: %s", err)
	}
	return lastIdx
}

func writeExperimentIdx(lastIdx int64) {
	file, err := os.Create("/home/cyrill/go/src/github.com/cyrill-k/trustflex/tls/experimentIdx")
	common.LogError("Failed to create lastIdx file: %s", err)
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("%d", lastIdx))
	common.LogError("Failed writing lastIdx to file: %s", err)

}

func main() {
	order := binary.LittleEndian

	var err error

	reader := bufio.NewReader(os.Stdin)

	repeat := int64(1)

	// for {
	var req MsgReq
	err = req.Read(reader, order)
	if err != nil {
		if err != io.EOF {
			// writeResponse(req.Domain, fmt.Errorf("ReadError: %s", err), order)
			return
		}
		return
		// continue
	}

	f, err := os.Open("/home/cyrill/go/src/github.com/cyrill-k/trustflex/tls/experiment-domains")
	common.LogError("Can't open perf log file: %s", err)
	allDomains, err := ioutil.ReadAll(f)
	common.LogError("Can't read domains from file: %s", err)

	expIdx := readExperimentIdx()
	var allDomainsSplit []string
	for _, s := range strings.Split(string(allDomains), "\n") {
		// ignore empty line at end of file
		if s != "" {
			allDomainsSplit = append(allDomainsSplit, s)
		}
	}
	idx := (expIdx / repeat) % int64(len(allDomainsSplit))
	log.Printf("expIdx = %d, idx = %d", expIdx, idx)
	rankedDomain := allDomainsSplit[idx]
	rankedDomainSplit := strings.Split(rankedDomain, ",")
	rank, err := strconv.Atoi(rankedDomainSplit[0])
	if err != nil {
		common.Log("Failed to parse rank (expIdx=%d, idx=%d): %s", expIdx, idx, err)
		return
	}

	writeExperimentIdx(expIdx + 1)
	writeResponse(rank, rankedDomainSplit[1], order)
}

func writeResponse(rank int, domain string, order binary.ByteOrder) {
	res := MsgRes{rank, domain}
	err := res.Write(os.Stdout, order)
	if err != nil {
		fmt.Fprint(os.Stderr, "WriteError: ", err, "\n")
		// continue
	}

}
