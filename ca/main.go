// This file holds code to generate EECerts.
// Adapted from https://golang.org/src/crypto/tls/generate_cert.go

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/cyrill-k/fpki/common"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var (
	outFile      = flag.String("out_cert", "data/generated_ee_cert.pem", "Name of the output certificate file")
	outKeyFile   = flag.String("out_key", "data/generated_key.pem", "Name of the output private key file")
	host         = flag.String("host", "", "Comma-separated host-names and IPs to generate a certificate for")
	isEECert     = flag.Bool("is_ee_cert", true, "Generation of EECert")
	subject      = flag.String("subject", "CH,Example,ZH,www.example.ch", "Certificate's owner information, comma separated")
	duration     = flag.Duration("duration", 10*365*24*time.Hour, "Certificate's duration")
	isCA         = flag.Bool("ca", false, "CA certificate")
	isSelfSigned = flag.Bool("self", false, "Self-signed certificate")
	rsaBits      = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve   = flag.String("ecdsa-curve", "",
		"ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
	issuerFile    = flag.String("issuer_cert", "data/ca1_cert.pem", "Name of issuer certificate file")
	issuerKeyFile = flag.String("issuer_key", "data/ca1_key.pem", "Name of issuer key file")
	inKeyFile     = flag.String("in_key", "", "Name of the key file used as the public key of the signed certificate")
	isUnique      = flag.Bool("policy-unique", false, "whether certificates with different public keys are allowed or not")
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func createCertificate(priv_signer, pub_signee interface{}, caCert *x509.Certificate, subj []string) []byte {
	notBefore := time.Now()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	subjectKeyId, err := common.IDFromPublicKey(pub_signee)
	if err != nil {
		log.Fatalf("failed to create SubjectKeyId: %s", err)
	}
	authorityKeyId, err := common.IDFromPublicKey(publicKey(priv_signer))
	if err != nil {
		log.Fatalf("failed to create AuthorityKeyId: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      append([]string{}, subj[0]),
			Organization: append([]string{}, subj[1]),
			Locality:     append([]string{}, subj[2]),
			CommonName:   subj[3],
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(*duration),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		SubjectKeyId:          subjectKeyId.Bytes(),
		AuthorityKeyId:        authorityKeyId.Bytes(),
		BasicConstraintsValid: true,
	}

	if *isUnique {
		uniqueExt := common.X509BoolExtension{Inherited: true, Value: true}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: common.OIDExtensionUNIQUE, Critical: false, Value: uniqueExt.GetValue()})
	}

	hosts := strings.Split(*host, ",")
	for _, h := range hosts {
		if h == "" {
			// do not add empty domains
		} else if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if *isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	var derBytes []byte
	if *isSelfSigned {
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, pub_signee, priv_signer)
		common.LogError("Failed to create self signed certificate: %s", err)
	} else {
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, caCert, pub_signee, priv_signer)
		common.LogError("Failed to create certificate: %s", err)
	}

	return derBytes
}

func generateKeys() (interface{}, error) {
	var priv interface{}
	var err error
	switch *ecdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, *rsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	default:
		fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", *ecdsaCurve)
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}
	return priv, err
}

func writePrivateKeyToFile(priv interface{}) {
	keyOut, err := os.OpenFile(*outKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", *outKeyFile, err)
	}
	if err := pem.Encode(keyOut, pemBlockForKey(priv)); err != nil {
		log.Fatalf("Failed to write data to %s: %s", *outKeyFile, err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing %s: %s", *outKeyFile, err)
	}
	log.Printf("Wrote %s\n", *outKeyFile)
}

func readPrivateKeyFromFile(p string) interface{} {
	keyBytes, err := common.KeyFromPEM(p)
	if err != nil {
		log.Fatalf("Failed to open key file %s: %s", p, err)
	}
	if key, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return key
	} else if key, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return key
	} else {
		log.Fatalf("Failed to convert key file: %s", p, err)
		return nil
	}
}

func main() {
	flag.Parse()

	// subj := strings.Split(*subject, ",")
	// if len(subj) < 4 {
	// 	log.Fatal("At least 4 values (Organization, Country, Location, Common Name) must be specified")
	// }

	// var priv interface{}
	// priv, _ = generateKeys()
	// subjectKeyId, err := common.IDFromPublicKey(publicKey(priv))
	// if err != nil {
	// 	log.Fatalf("failed to create SubjectKeyId: %s", err)
	// }
	// log.Printf("CA subjectKeyId: %x", subjectKeyId.Bytes())

	// bytesCert := createCertificate(priv, publicKey(priv), nil, subj)
	// log.Printf("cert = %s", bytesCert)

	// return

	// cert, err := common.X509CertFromPEM("data/r1/server6_cert.pem")
	// if err != nil {
	// 	log.Printf("Error parsing pem: %s", err)
	// }
	// log.Printf("cert: %+v", cert)
	// chains, err := common.X509Verify([]x509.Certificate{*cert})
	// log.Printf("err: %s", err)
	// log.Printf("len: %d", len(chains))
	// log.Printf("chains[0][0]: %+v", chains[0][0])
	// log.Printf("chains[0][1]: %+v", chains[0][1])
	// log.Printf("cershort: %s", common.X509CertToString(cert))
	// return

	subj := strings.Split(*subject, ",")
	if len(subj) < 4 {
		log.Fatal("At least 4 values (Organization, Country, Location, Common Name) must be specified")
	}

	var priv interface{}
	if *inKeyFile == "" {
		priv, _ = generateKeys()
	} else {
		priv = readPrivateKeyFromFile(*inKeyFile)
	}

	if *isSelfSigned {
		subjectKeyId, err := common.IDFromPublicKey(publicKey(priv))
		if err != nil {
			log.Fatalf("failed to create SubjectKeyId: %s", err)
		}
		log.Printf("CA subjectKeyId: %x", subjectKeyId.Bytes())

		bytesCert := createCertificate(priv, publicKey(priv), nil, subj)
		common.WriteCertBytesToFile(bytesCert, *outFile)
		writePrivateKeyToFile(priv)
		return
	}

	issuer_cert, err := common.CertFromFile(*issuerFile)
	if err != nil {
		log.Fatalf("Failed to open certificate %s: %s", *issuerFile, err)
	}
	issuer_key := readPrivateKeyFromFile(*issuerKeyFile)
	bytesCert := createCertificate(issuer_key, publicKey(priv), issuer_cert, subj)
	common.WriteCertBytesToFile(bytesCert, *outFile)
	writePrivateKeyToFile(priv)
}
