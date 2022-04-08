package main

import (
	"bufio"
	"crypto/x509"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/cyrill-k/trustflex/common"
	"github.com/cyrill-k/trustflex/dns/util"
	"github.com/cyrill-k/trustflex/trillian/tclient"
	"io"
	"log"
	"os"
	"time"
)

var (
	cmd = flag.String("cmd", "verify", "Command to execute")

	mapResolverAddress = flag.String("map_res_addr", "127.0.0.53:53", "Address of the dns resolver of the map server")
	mapResolverDomain  = flag.String("map_res_domain", "mapserver1.com", "DNS domain name of map server")

	mapID = flag.Int64("map_id", 0, "ID of the Trillian Map")
	mapPk = flag.String("map_pk", "data/os-trustflex-dnsresolver/mappk1.pem", "File holding Map Public Key")

	domain = flag.String("domain", "example.com", "Domain that should be queried")

	rankedDomainFile = flag.String("domain-file", "data/e2e.csv", "csv file with columns rank and domain")
	outputFile       = flag.String("out", "data/golang-client-perf.csv", "csv file with columns rank, domain, proof retrieval time, and proof validation time")
)

func verifyAll() {
	common.EnableDebug = false
	fIn, err := os.Open(*rankedDomainFile)
	common.LogError("Can't open perf log file: %s", err)
	r := bufio.NewReader(fIn)
	csvReader := csv.NewReader(r)

	fOut, err := common.OpenOrCreate(*outputFile)
	common.LogError("Can't open output file: %s", err)
	w := bufio.NewWriter(fOut)
	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		common.LogError("Error reading csv file: %s", err)

		log.Print(record)

		var csvMsg string
		start := time.Now()
		proofBytes, err := common.RetrieveTxtRecord(record[1]+"."+*mapResolverDomain+".", "178.128.207.154:12345", true)
		//common.LogError("Failed to retrieve txt record from remote: %s", err)
		if err != nil {
			csvMsg += ".remote-fail"
		}
		elapsed1remote := time.Since(start)

		start = time.Now()
		proofBytes, err = common.RetrieveTxtRecord(record[1]+"."+*mapResolverDomain+".", *mapResolverAddress, true)
		if err != nil {
			csvMsg += ".local-fail"
		}
		//common.LogError("Failed to retrieve txt record from local: %s", err)
		elapsed1local := time.Since(start)

		start = time.Now()
		_, err = util.GetVerifiedPolicy(record[1], proofBytes, *mapID, *mapPk, nil, true)
		if err != nil {
			common.Log("Error verifying policy: %s", err)
		}
		elapsedGetPolicy := time.Since(start)

		if len(proofBytes) > 0 {
			proof := tclient.NewProof()
			proof.SetEnableCompression(true)
			err = proof.UnmarshalBinary(proofBytes)
			if err := proof.UnmarshalBinary(proofBytes); err != nil {
				csvMsg += ".unmarshal-fail"
				//common.LogError("Failed to unmarshal proof: %s", err)
			}
			proof.SetDomain(record[1])
			common.Debug("Retrieved proof for %s: %s", record[1], proof.ToString())

			certs := proof.GetUnrevokedCertificates(record[1])
			if len(certs) == 0 {
				common.Log("The certificate has no certificate: %s", err)
				csvMsg += ".get-cert-fail"
				certs = [][]x509.Certificate{nil}
			}
			start = time.Now()
			// log.Printf("%+v", *mapID)
			err = util.VerifyTrustflex(record[1], proofBytes, certs[0], *mapID, *mapPk, nil, true)
			if err != nil {
				common.Log("Verification failed: %s", err)
				csvMsg += ".verify-fail"
			}
			//common.LogError("Failed to Verify proof: %s", err)
		}
		elapsed2 := time.Since(start)

		if len(csvMsg) == 0 {
			csvMsg = "success"
		}
		csvWriter.Write([]string{record[0], record[1], fmt.Sprintf("%d", elapsed1local.Nanoseconds()), fmt.Sprintf("%d", elapsed1remote.Nanoseconds()), fmt.Sprintf("%d", elapsed2.Nanoseconds()), fmt.Sprintf("%d", elapsedGetPolicy.Nanoseconds()), csvMsg})
	}
}

func main() {
	flag.Parse()

	switch *cmd {
	case "verify":
		proofBytes, err := common.RetrieveTxtRecord(*domain+"."+*mapResolverDomain+".", *mapResolverAddress, true)
		common.LogError("Failed to retrieve txt record: %s", err)
		// add google root CA as trusted CA (0x9be20757671c1ec06a06de59b49a2ddfdc19862e)
		// err = util.VerifyTrustflex(*domain, proofBytes, nil, *mapID, *mapPk, [][]byte{[]byte{0x9b, 0xe2, 0x07, 0x57, 0x67, 0x1c, 0x1e, 0xc0, 0x6a, 0x06, 0xde, 0x59, 0xb4, 0x9a, 0x2d, 0xdf, 0xdc, 0x19, 0x86, 0x2e}}, true)
		err = util.VerifyTrustflex(*domain, proofBytes, nil, *mapID, *mapPk, nil, true)
		common.LogError("Failed to Verify proof: %s", err)
		common.Log("Success")
	case "verify-all":
		verifyAll()
	default:
		log.Fatal("Supplied command is not supported")
	}
}
