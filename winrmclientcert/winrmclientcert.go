package winrmclientcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"
)

type WinrmClientCert struct {
	Subject           pkix.Name
	ValidFrom         string
	ValidFor          time.Duration
	RsaBits           int
	EcdsaCurve        string
	CertificateExport io.Writer
	PrivateKeyExport  io.Writer
}

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

type KeyPurposeId struct {
	OID asn1.ObjectIdentifier
}

type OtherName struct {
	A string `asn1:"utf8"`
}

type GeneralName struct {
	OID       asn1.ObjectIdentifier
	OtherName `asn1:"tag:0"`
}

type GeneralNames struct {
	GeneralName `asn1:"tag:0"`
}

func NewWinrmClientCertificate(c WinrmClientCert) error {
	var priv interface{}
	var err error

	switch c.EcdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, c.RsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return fmt.Errorf("Unrecognized elliptic curve: %q", c.EcdsaCurve)
	}

	if err != nil {
		return fmt.Errorf("Failed to generate private key: %s", err)
	}

	var notBefore time.Time
	if c.ValidFrom == "" {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", c.ValidFrom)
		if err != nil {
			return fmt.Errorf("Failed to parse creation date: %s", err)
		}
	}

	notAfter := notBefore.Add(c.ValidFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 4)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("Failed to generate serial number: %s", err)
	}

	oidOtherName := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	mycommonName := OtherName{c.Subject.CommonName}

	sequence := GeneralName{
		OID:       oidOtherName,
		OtherName: mycommonName,
	}

	val, err := asn1.Marshal(GeneralNames{sequence})

	if err != nil {
		return err
	}

	template := x509.Certificate{
		Subject: c.Subject,

		SerialNumber:       serialNumber,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: x509.SHA1WithRSA,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},

		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 17},
				Critical: false,
				Value:    val,
			},
		},
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %s", err)
	}

	if c.CertificateExport != nil {
		pem.Encode(c.CertificateExport, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	}

	if c.PrivateKeyExport != nil {
		pem.Encode(c.PrivateKeyExport, pemBlockForKey(priv))
	}

	return nil
}
