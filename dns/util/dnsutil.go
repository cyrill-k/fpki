package util

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/cyrill-k/fpki/common"
	"github.com/cyrill-k/fpki/trillian/tclient"
)

type ProofDebugInfo struct {
	NCertificates         []int64
	NWildcardCertificates []int64
}

func VerifyFpki(domain string, proofBytes []byte, certificate []x509.Certificate, mapID int64, mapPK string, trustedCAs [][]byte, compressed bool) error {
	policy, _, err := GetVerifiedPolicy(domain, proofBytes, mapID, mapPK, trustedCAs, compressed)
	if err != nil {
		return err
	}
	return VerifyFpkiPolicy(policy, certificate)
}

// verify the TLS certificate given the resolved and verified policy
func VerifyFpkiPolicy(policy map[string]interface{}, certificate []x509.Certificate) error {
	// HTTP downgrade prevention
	common.Debug("Checking for HTTP downgrade attack...")
	if len(certificate) == 0 && !policy["_ALLOW_HTTP"].(bool) {
		// HTTP connection was initiated (no certificate present)
		return fmt.Errorf("Downgrade attack detected")
	}

	// verify policy
	if policy["UNIQUE"].(bool) {
		common.Debug("Checking for public key uniqueness...")
		id, err := common.IDFromPublicKey(certificate[0].PublicKey)
		if err != nil {
			return fmt.Errorf("Couldn't generate id from public key: %s", err)
		}
		if !bytes.Equal(policy["UNIQUE_PK"].([]byte), id.Bytes()) {
			fmt.Errorf("Public Key is not unique among all trusted certificates and TLS certificate")
		}
	}
	return nil
}

// we assume that certificate is already verified using the Web PKI
func GetVerifiedPolicy(domain string, proofBytes []byte, mapID int64, mapPK string, trustedCAs [][]byte, compressed bool) (map[string]interface{}, ProofDebugInfo, error) {
	proof := tclient.NewProof()
	proof.SetEnableCompression(compressed)
	err := proof.UnmarshalBinary(proofBytes)
	if err := proof.UnmarshalBinary(proofBytes); err != nil {
		return nil, ProofDebugInfo{}, fmt.Errorf("Failed to unmarshal proof: %s", err)
	}
	proof.SetDomain(domain)
	common.Debug("Retrieved proof for %s: %s", domain, proof.ToString())

	// validate proof
	t1 := time.Now()
	pubKey, err := common.LoadPK(mapPK)
	if err != nil {
		return nil, ProofDebugInfo{}, fmt.Errorf("Failed to parse public key: %s", err)
	}
	err = proof.Validate(mapID, pubKey, common.DefaultTreeNonce, domain)
	if err != nil {
		return nil, ProofDebugInfo{}, fmt.Errorf("Failed to validate proof received via DNS: %s", err)
	}

	// extract all relevant certificates (unrevoked and signed by trusted CA) from proof
	proofCerts := proof.GetUnrevokedCertificatesSignedByCAs(domain, trustedCAs)
	var unrevokedCerts string
	for i, c := range proofCerts {
		if i > 0 {
			unrevokedCerts += ", "
		}
		unrevokedCerts += common.X509CertChainToString(c)
	}
	common.Debug("Unrevoked certs signed by trusted CAs (%d): %s", len(proofCerts), unrevokedCerts)

	// resolve policy
	policy, err := common.ResolvePolicy(domain, proofCerts)
	if err != nil {
		return nil, ProofDebugInfo{}, fmt.Errorf("Couldn't resolve policy: %s", err)
	}

	unrevoked := proof.GetUnrevokedCertificates(domain)
	policy["_ALLOW_HTTP"] = len(unrevoked) == 0

	// common.Log("unrevoked: %s", common.X509CertChainToString(unrevoked[0]))
	// common.Log("unrevoked subject pk: %+v", unrevoked[0][0].RawSubjectPublicKeyInfo)
	// o, _ := common.SubjectPublicKeyInfoDigest(&unrevoked[0][0])
	// common.Log("id: %x", o)
	// if len(unrevoked) > 0 {
	// 	digest, _ := common.SubjectPublicKeyInfoDigest(&unrevoked[0][0])
	// 	policy["UNIQUE_PK"] = digest.Bytes()
	// }

	// verify policy
	if policy["UNIQUE"].(bool) {
		var id common.ID
		for _, c := range proofCerts {
			idPol, err := common.SubjectPublicKeyInfoDigest(&c[0])
			if len(id) == 0 {
				// initialize id if not set already
				id = idPol
			}
			if err != nil {
				return nil, ProofDebugInfo{}, fmt.Errorf("Couldn't generate id from public key: %s", err)
			}
			if !bytes.Equal(id.Bytes(), idPol.Bytes()) {
				return nil, ProofDebugInfo{}, fmt.Errorf("Public Key is not unique among all certificates")
			}
		}
		policy["UNIQUE_PK"] = id.Bytes()
	}

	t2 := time.Now()
	common.Debug("validation = %s", t2.Sub(t1))

	n_entries := proof.GetNumberOfEntries()
	certs := make([]int64, n_entries)
	wcerts := make([]int64, n_entries)
	for i := 0; i < n_entries; i++ {
		me := proof.GetEntry(i)
		certs[i] = int64(len(me.GetCertificates()))
		wcerts[i] = int64(len(me.GetWildcardCertificates()))
	}
	return policy, ProofDebugInfo{NCertificates: certs, NWildcardCertificates: wcerts}, nil
}
