//Package crl implements the crl command
package crl

import (
	"os"

	"github.com/cloudflare/cfssl/certdb/db"
	"github.com/cloudflare/cfssl/certdb/dbconf"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/crl"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
)

var crlUsageText = `cfssl crl -- generate a new Certificate Revocation List from Database

Usage of crl:
        cfssl crl

Flags:
`
var crlFlags = []string{"db-config", "ca", "ca-key", "expiry"}

func generateCRL(c cli.Config) (crlBytes []byte, err error) {
	if c.CAFile == "" {
		log.Error("need CA certificate (provide one with -ca)")
		return
	}

	if c.CAKeyFile == "" {
		log.Error("need CA key (provide one with -ca-key)")
		return
	}

	cfg, err := dbconf.LoadFile(c.DBConfigFile)
	if err != nil {
		return nil, err
	}

	dbAccessor, err := db.NewAccessor(cfg)
	if err != nil {
		return nil, err
	}

	log.Debug("loading CA: ", c.CAFile)
	ca, err := helpers.ReadBytes(c.CAFile)
	if err != nil {
		return nil, err
	}
	log.Debug("loading CA key: ", c.CAKeyFile)
	cakey, err := helpers.ReadBytes(c.CAKeyFile)
	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ReadFailed, err)
	}

	// Parse the PEM encoded certificate
	issuerCert, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return nil, err
	}

	strPassword := os.Getenv("CFSSL_CA_PK_PASSWORD")
	password := []byte(strPassword)
	if strPassword == "" {
		password = nil
	}

	// Parse the key given
	key, err := helpers.ParsePrivateKeyPEMWithPassword(cakey, password)
	if err != nil {
		log.Debug("malformed private key %v", err)
		return nil, err
	}

	certs, err := dbAccessor.GetRevokedAndUnexpiredCertificates()
	if err != nil {
		return nil, err
	}

	req, err := crl.NewCRLFromDB(certs, issuerCert, key, c.CRLExpiration)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func crlMain(args []string, c cli.Config) (err error) {
	req, err := generateCRL(c)
	if err != nil {
		return err
	}

	cli.PrintCRL(req)
	return
}

// Command assembles the definition of Command 'crl'
var Command = &cli.Command{UsageText: crlUsageText, Flags: crlFlags, Main: crlMain}
