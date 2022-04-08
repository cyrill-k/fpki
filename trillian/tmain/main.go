package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"time"

	"github.com/cyrill-k/fpki/common"
	"github.com/cyrill-k/fpki/trillian/mapper"
	"github.com/cyrill-k/fpki/trillian/tclient"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	"github.com/google/trillian/client/rpcflags"
	"google.golang.org/grpc"
)

var (
	cmd = flag.String("cmd", "", "Command to execute")

	logID      = flag.Int64("log_id", 0, "ID of the Trillian Log")
	logAddress = flag.String("log_addr", "localhost:8090", "Address of the Trillian Log (host:port)")
	logPk      = flag.String("log_pk", "data/log_pk.pem", "File holding Log Public Key")

	mapID      = flag.Int64("map_id", 0, "ID of the Trillian Map")
	mapAddress = flag.String("map_addr", "localhost:8094", "Address of the Trillian Map (host:port)")
	mapPk      = flag.String("map_pk", "data/map_pk.pem", "File holding Map Public Key")

	ctLogAddress = flag.String("ct_log_addr", "", "URL of the CT Log")

	certFile = flag.String("cert_file", "-", "File name pointing to the certificate to log")

	domain = flag.String("domain", "example.com", "Domain that should be queried")

	first                 = flag.Bool("first", false, "Indicates whether it is the first time performing the mapping")
	validDomains          = flag.String("valid-domains", "data/valid.gob", "File name to store all valid domain names")
	invalidDomains        = flag.String("invalid-domains", "data/invalid.gob", "File name to store all invalid domain names")
	timeStats             = flag.String("time_stats", "data/time.gob", "File name to store map retrieval times (lastIdx => [time in ns])")
	sizeStats             = flag.String("size_stats", "data/size.gob", "File name to store proof sizes (lastIdx => [space in bytes])")
	incsizeStats          = flag.String("inc_size_stats", "data/incsize.gob", "File name to store inclusion proof sizes (lastIdx => [space in bytes])")
	mapElements           = flag.Int64("map_elements", 1000, "Map up to this amount of log entries")
	maxReceiveMessageSize = flag.Int("max_receive_message_size", 0, "Set the maximum grpc receive message size")
	ppiFile               = flag.String("ppi_file", "data/ppi.csv", "Csv file where the statistics from the map server are stored")
	droppedPacketFile     = flag.String("dropped_file", "data/dropped.csv", "Csv file where the dropped certificate entries from the CT log are stored")
	debug                 = flag.Bool("debug", false, "Indicates whether debug messages should be logged")
	proof_output_folder   = flag.String("proof_output", "", "Folder where the retrieved proofs should be stored (filename is <domain>.proof)")
)

func getAllServerCerts(certFolder string) []*x509.Certificate {
	return common.X509GetCerts(certFolder, "server\\d+_cert.pem")
}

func getAllDomains() []string {
	var allDomains []string
	for _, c := range getAllServerCerts("data") {
		for _, d := range common.DomainsFromX509Cert(c) {
			if !common.SliceIncludes(allDomains, d) {
				allDomains = append(allDomains, d)
			}
		}
	}
	return allDomains
}

func retrieveCerts() {
	logClient := tclient.NewLogClient(*logAddress, *logPk, *maxReceiveMessageSize)
	defer logClient.Close()
	logClient.RetrieveCerts(*logID, 0)
}

func retrieveFromMap() {
	proofs, err := retrieveProofsFromMapForDomains([]string{*domain})
	if err != nil {
		log.Fatal(err)
	}

	if *proof_output_folder == "" && len(proofs) == 1 {
		proofBytes, err := proofs[0].MarshalBinary()
		if err != nil {
			log.Fatalf("Domain %s: Failed to marshal binary: %s", *domain, err)
		}
		writer := io.Writer(os.Stdout)
		writer.Write(proofBytes)
	}
	// for i, c := range p[0].GetEntry(1).GetCertificates() {
	// 	for j, x := range c {
	// 		// if j == 0 {
	// 		// 	log.Printf("%d, %d: %+v", i, j, x)
	// 		// } else {
	// 		log.Printf("%d, %d: %+v", i, j, common.X509CertToString(&x))
	// 		// }
	// 	}
	// }
}

func readLastIdx() int64 {
	var lastIdx int64
	lastIdx = 0
	if !*first {
		file, _ := os.Open("trillian/lastIdx")
		// common.LogError("Failed to open lastIdx file: %s", err)
		defer file.Close()

		_, _ = fmt.Fscanf(file, "%d", &lastIdx)
		// common.LogError("Failed reading lastIdx: %s", err)
	}
	return lastIdx
}

func extractProofPerformanceInfo(domain string, currentIdx int64, p tclient.Proof, getProofTime time.Duration) (common.ProofPerformanceInfo, error) {
	ppi := common.ProofPerformanceInfo{CurrentIdx: currentIdx, Domain: domain, GetProofTime: getProofTime.Nanoseconds()}
	rootCertAKIs := make(map[[32]byte]int64)

	certs := make(map[[32]byte]int64)
	certSizes := make(map[[32]byte]int64)

	leafCerts := make(map[[32]byte]int64)
	leafPublicKeys := make(map[[32]byte]int64)

	leafPublicKeysExactDomain := make(map[[32]byte]int64)
	leafCertificatesExactDomain := make(map[[32]byte]int64)

	leafCertsWildcard := make(map[[32]byte]int64)
	leafPublicKeysWildcard := make(map[[32]byte]int64)

	nEntries := p.GetNumberOfEntries()
	for i := 0; i < nEntries; i++ {
		for _, c := range p.GetEntry(i).GetCertificates() {
			for k, x := range c {
				cID := common.X509ID(&x)
				certs[cID] += 1
				certSizes[cID] = int64(len(x.Raw))
				pID, err := common.IDFromPublicKey(x.PublicKey)
				if err != nil {
					return common.ProofPerformanceInfo{}, err
				}
				if k == 0 {
					leafCerts[cID] += 1
					leafPublicKeys[pID] += 1
					if common.X509ContainsDomain(&x, domain) {
						leafCertificatesExactDomain[cID] += 1
						leafPublicKeysExactDomain[pID] += 1
					}
					if common.X509MatchesDomain(&x, domain) {
						leafCertsWildcard[cID] += 1
						leafPublicKeysWildcard[pID] += 1
					}
				}
				if k == len(c)-1 {
					rootCertAKIs[common.IDFromAuthorityKeyId(&x)] += 1
				}
			}
		}
		for _, c := range p.GetEntry(i).GetWildcardCertificates() {
			for k, x := range c {
				cID := common.X509ID(&x)
				certs[cID] += 1
				certSizes[cID] = int64(len(x.Raw))
				pID, err := common.IDFromPublicKey(x.PublicKey)
				if err != nil {
					return common.ProofPerformanceInfo{}, err
				}
				if k == 0 {
					leafCerts[cID] += 1
					leafPublicKeys[pID] += 1
					if common.X509ContainsDomain(&x, domain) {
						leafCertificatesExactDomain[cID] += 1
						leafPublicKeysExactDomain[pID] += 1
					}
					if common.X509MatchesDomain(&x, domain) {
						leafCertsWildcard[cID] += 1
						leafPublicKeysWildcard[pID] += 1
					}
				}
				if k == len(c)-1 {
					rootCertAKIs[common.IDFromAuthorityKeyId(&x)] += 1
				}
			}
		}
	}
	ppi.NCertificates = countAll(certs)
	ppi.NUniqueCertificates = int64(len(certs))
	for c := range certs {
		ppi.UniqueCertificatesSize += certSizes[c]
	}
	ppi.NLeafCertificates = int64(len(leafCerts))
	ppi.NUniquePublicKeys = int64(len(leafPublicKeys))
	ppi.NLeafCertificatesForExactDomain = int64(len(leafCertificatesExactDomain))
	ppi.NUniquePublicKeysForExactDomain = int64(len(leafPublicKeysExactDomain))
	ppi.NLeafCertificatesForExactDomainOrWildcard = int64(len(leafCertsWildcard))
	ppi.NUniquePublicKeysForExactDomainOrWildcard = int64(len(leafPublicKeysWildcard))
	ppi.NUniqueRootCACertificates = int64(len(rootCertAKIs))

	p.SetEnableCompression(false)
	data, err := p.MarshalBinary()
	if err != nil {
		return common.ProofPerformanceInfo{}, fmt.Errorf("Couldn't marshal proof without compression: %s", err)
	}
	ppi.ProofSize = int64(len(data))

	is, err := p.GetInclusionProofSize()
	if err != nil {
		return common.ProofPerformanceInfo{}, fmt.Errorf("Couldn't get inclusion proof size: %s", err)
	}
	ppi.InclusionProofSize = int64(is)

	p.SetEnableCompression(true)
	data, err = p.MarshalBinary()
	if err != nil {
		return common.ProofPerformanceInfo{}, fmt.Errorf("Couldn't marshal proof with compression: %s", err)
	}
	ppi.CompressedProofSize = int64(len(data))
	return ppi, nil
}

func countAll(m map[[32]byte]int64) (n int64) {
	for _, v := range m {
		n += v
	}
	return
}

func getProofPerformanceStats() {
	getProofPerformanceStatsForDomains([]string{*domain})
}

func getProofPerformanceStatsForAllDomains() {
	var d map[string]bool
	common.GobReadMapBool(*validDomains, &d)
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	getProofPerformanceStatsForDomains(keys)
}

func getProofPerformanceStatsForDomains(d []string) {
	lastIdx := readLastIdx()
	mapClient := tclient.NewMapClient(*mapAddress, *mapPk, *maxReceiveMessageSize)
	defer mapClient.Close()
	var w io.Writer
	if *ppiFile == "-" {
		w = bufio.NewWriter(os.Stdout)
	} else {
		f, err := common.OpenOrCreate(*ppiFile)
		common.LogError("Can't open ppi file: %s", err)
		w = bufio.NewWriter(f)
	}
	ppiWriter := common.NewProofPerformanceInfoWriter(w)
	defer ppiWriter.Close()
	for _, k := range d {
		start := time.Now()
		proofs, err := mapClient.GetProofForDomains(*mapID, mapClient.GetMapPK(), []string{k})
		elapsed := time.Since(start)
		common.LogError("Couldn't fetch proof: %s", err)
		ppi, err := extractProofPerformanceInfo(k, lastIdx, proofs[0], elapsed)
		common.LogError("Couldn't extract proof performance info: %s", err)
		ppiWriter.StoreProofPerformanceInfoEntry(&ppi)
	}
}

func sanitizeProof() {
	sanitizeProofsForDomains([]string{*domain})
}

func sanitizeProofsForAllDomains() {
	sanitizeProofsForDomains(getAllDomains())
}

func sanitizeProofsForDomains(domains []string) {
	mapClient := tclient.NewMapClient(*mapAddress, *mapPk, *maxReceiveMessageSize)
	defer mapClient.Close()

	proofs, err := mapClient.GetProofForDomains(*mapID, mapClient.GetMapPK(), domains)
	common.LogError("Couldn't retrieve proofs for all domains: %s", err)

	log.Print("Entries in map server...")
	for i, proof := range proofs {
		err := proof.Validate(*mapID, mapClient.GetMapPK(), common.DefaultTreeNonce, domains[i])
		if err != nil {
			log.Fatalf("Entry %d (%s): Validate failed: %s", i, proof.GetDomain(), err)
		}
		log.Printf("Entry %d (%s): %s", i, proof.GetDomain(), proof.ToString())
	}

	log.Printf("sanitizing %s ...", *mapPk)
	mper, err := mapper.NewMapper(*mapAddress, *mapPk, *validDomains, *invalidDomains, *droppedPacketFile, *maxReceiveMessageSize)
	defer mper.Close()
	if err != nil {
		common.LogError("Couldn't create mapper: %s", err)
	}

	err = mper.PerformMappingFromProofs(proofs, *mapID, 100)
	common.LogError("Sanitizing failed: %s", err)
}

func retrieveFromMapForAllDomains() {
	retrieveProofsFromMapForDomains(getAllDomains())
}

func retrieveProofsFromMapForDomains(domains []string) ([]tclient.Proof, error) {
	mapClient := tclient.NewMapClient(*mapAddress, *mapPk, *maxReceiveMessageSize)
	defer mapClient.Close()

	proofs, err := mapClient.GetProofForDomains(*mapID, mapClient.GetMapPK(), domains)
	common.LogError("Couldn't retrieve proofs for all domains: %s", err)

	log.Print("Entries in map server...")
	for i, proof := range proofs {
		err := proof.Validate(*mapID, mapClient.GetMapPK(), common.DefaultTreeNonce, domains[i])
		if err != nil {
			log.Fatalf("Entry %d (%s): Validate failed: %s", i, proof.GetDomain(), err)
		}
		log.Printf("Entry %d (%s): %s", i, proof.GetDomain(), proof.ToString())

		proof.SetEnableCompression(true)

		if *proof_output_folder != "" {
			proofBytes, err := proof.MarshalBinary()
			if err != nil {
				log.Fatalf("Entry %d (%s): Failed to marshal binary: %s", i, proof.GetDomain(), err)
			}
			ioutil.WriteFile(path.Join(*proof_output_folder, domains[i]), proofBytes, 0644)
		}
	}
	return proofs, nil
}

func mapping() {
	log.Printf("mapping %s", *mapPk)
	mper, err := mapper.NewMapper(*mapAddress, *mapPk, *validDomains, *invalidDomains, *droppedPacketFile, *maxReceiveMessageSize)
	if err != nil {
		common.LogError("Couldn't create mapper: %s", err)
	}
	defer mper.Close()

	lastIdx := readLastIdx()
	lastIdx, err = mper.PerformMapping(*logAddress, *logPk, *logID, *mapID, lastIdx)
	common.LogError("Mapping failed: %s", err)
}

func mappingFromCTLog() {
	log.Printf("mapping from CT log %s", *mapPk)
	mper, err := mapper.NewMapper(*mapAddress, *mapPk, *validDomains, *invalidDomains, *droppedPacketFile, *maxReceiveMessageSize)
	defer mper.Close()
	if err != nil {
		common.LogError("Couldn't create mapper: %s", err)
	}

	lastIdx := readLastIdx()
	common.Log("ctLogAddress=%s", *ctLogAddress)
	common.Log("lastIdx=%d", lastIdx)
	lastIdx, err = mper.PerformMappingFromCTLog(*ctLogAddress, *mapID, lastIdx, lastIdx+*mapElements, common.Min(100, *mapElements))
	common.Log("lastIdx: %d, Domains(%d invalid, %d valid): %s", lastIdx, len(mper.InvalidDomains()), len(mper.ValidDomains()), *ctLogAddress)
	common.LogError("Mapping failed: %s", err)
}

func checkMapID() {
	if *mapID == 0 {
		log.Fatal("A mapID must be specified")
	}
}

func checkLogID() {
	if *logID == 0 {
		log.Fatal("A logID must be specified")
	}
}

func checkFileName() {
	if *certFile == "" {
		log.Fatal("A certificate file name must be specified")
	}
}

func addCert() {
	logClient := tclient.NewLogClient(*logAddress, *logPk, *maxReceiveMessageSize)
	defer logClient.Close()
	var reader io.Reader
	if *certFile == "-" {
		reader = bufio.NewReader(os.Stdin)
	} else {
		var err error
		reader, err = os.Open(*certFile)
		if err != nil {
			log.Fatalf("Failed to open cert file (%s): %s", *certFile, err)
		}
	}
	logClient.LogCert(*logID, reader)
}

func getAllTrees(showDeleted bool) []*trillian.Tree {
	// 	ManagedChannel channel =
	//     ManagedChannelBuilder
	//     .forAddress(host,port)
	//     .usePlaintext()
	//     .maxInboundMessageSize(9999999)
	//     .build();
	// DamlLedgerClient client = new DamlLedgerClient(Optional.empty(), channel);

	// connect to adminServer using rpc
	dialOpts, err := rpcflags.NewClientDialOptionsFromFlags()
	common.LogError("failed to determine dial options: %v", err)
	if *maxReceiveMessageSize != 0 {
		dialOpts = append(dialOpts, grpc.WithMaxMsgSize(*maxReceiveMessageSize))
	}
	conn, err := grpc.Dial(*logAddress, dialOpts...)
	common.LogError("failed to dial: %s", err)
	defer conn.Close()
	adminClient := trillian.NewTrillianAdminClient(conn)

	// request to list all trees
	req := &trillian.ListTreesRequest{ShowDeleted: showDeleted}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	resp, err := adminClient.ListTrees(ctx, req)
	common.LogError("Couldn't list trees: %s", err)

	return resp.Tree
}

func deleteTree(treeId int64) bool {
	// connect to adminServer using rpc
	dialOpts, err := rpcflags.NewClientDialOptionsFromFlags()
	common.LogError("failed to determine dial options: %v", err)
	conn, err := grpc.Dial(*logAddress, dialOpts...)
	common.LogError("failed to dial: %s", err)
	defer conn.Close()
	adminClient := trillian.NewTrillianAdminClient(conn)

	// request to list all trees
	req := &trillian.DeleteTreeRequest{TreeId: treeId}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	resp, err := adminClient.DeleteTree(ctx, req)
	common.LogError("Couldn't delete tree: %s", err)

	return resp.Deleted
}

func listTrees() {
	log.Printf("Listing all trees ...")
	trees := getAllTrees(true)

	log.Printf("Deleted trees:")
	for i, t := range trees {
		if t.Deleted {
			ts, err := ptypes.Timestamp(t.UpdateTime)
			common.LogError("Couldn't extract timestamp", err)
			log.Printf("    %d: id=%d, state=%s, type=%s, sig_algo=%s, update=%s", i, t.TreeId, t.TreeState, t.TreeType, t.SignatureAlgorithm, ts)
		}
	}

	log.Printf("Not deleted trees:")
	for i, t := range trees {
		if !t.Deleted {
			ts, err := ptypes.Timestamp(t.UpdateTime)
			common.LogError("Couldn't extract timestamp", err)
			log.Printf("    %d: id=%d, state=%s, type=%s, sig_algo=%s, update=%s", i, t.TreeId, t.TreeState, t.TreeType, t.SignatureAlgorithm, ts)
		}
	}
}

func deleteAllTrees() {
	log.Printf("Deleting all trees ...")
	trees := getAllTrees(false)

	for i, t := range trees {
		log.Printf("    %d: Deleting %d", i, t.TreeId)
		if !deleteTree(t.TreeId) {
			log.Fatalf("Couldn't delete tree: id=%d", t.TreeId)
		}
	}
	log.Printf("Finished deleting all trees")
}

func main() {
	flag.Parse()
	common.EnableDebug = *debug

	switch *cmd {

	// admin related calls
	case "list_trees":
		listTrees()

	case "delete_all_trees":
		deleteAllTrees()

		// log server related calls
	case "log_add":
		checkLogID()
		checkFileName()
		addCert()

	case "log_retrieve_all":
		checkLogID()
		retrieveCerts()

	// case "log_pop":
	// 	checkLogID()
	// 	checkFileName()
	// 	getLogPoP()

	// map server related calls
	case "map":
		checkLogID()
		checkMapID()
		mapping()

	case "ct_map":
		checkMapID()
		mappingFromCTLog()

	case "map_retrieve":
		checkMapID()
		retrieveFromMap()

	case "map_retrieve_all":
		checkMapID()
		retrieveFromMapForAllDomains()

	case "get_proof_stats":
		checkMapID()
		getProofPerformanceStats()

	case "get_proof_stats_all":
		checkMapID()
		getProofPerformanceStatsForAllDomains()

	case "sanitize_proof":
		checkMapID()
		sanitizeProof()

	case "sanitize_proof_all":
		checkMapID()
		sanitizeProofsForAllDomains()

	default:
		log.Fatal("Supplied command is not supported")
	}
}
