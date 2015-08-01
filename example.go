package main

import (
	"crypto/x509/pkix"
	"fmt"
	"os"
	"time"

	"github.com/claudiu-coblis/WinrmClientCertificate/winrmclientcert"
)

func main() {
	certFilename := "cert.pem"
	certOut, err := os.Create(certFilename)
	defer certOut.Close()

	if err != nil {
		fmt.Printf("Failed to open %s for writing: %s.\n", certFilename, err)
	}

	keyFilename := "private_key.key"
	keyOut, err := os.OpenFile(keyFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer keyOut.Close()

	if err != nil {
		fmt.Printf("Failed to open %s for writing: %s.\n", keyFilename, err)
		return
	}

	mycert := winrmclientcert.WinrmClientCert{
		Subject: pkix.Name{
			CommonName: "example@Example",
		},
		ValidFrom: "",
		ValidFor:  365 * 24 * time.Hour,
		RsaBits:   2048,

		CertificateExport: certOut,
		PrivateKeyExport:  keyOut,
	}

	err = winrmclientcert.NewWinrmClientCertificate(mycert)

	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	fmt.Printf("%s & %s\n", certFilename, keyFilename)
}
