package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func Verify(root_cert, target_cert string)bool{
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(root_cert))
	if !ok {
		fmt.Errorf("parse root certificate error\n")
		return ok
	}
	block, _ := pem.Decode([]byte(target_cert))
	if block == nil {
		fmt.Errorf("parse target certificate error\n")
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Errorf("failed to parse certificate:%s\n", err.Error())
		return false
	}
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		fmt.Println("failed to verify certificate", err.Error())
		return false
	}
	fmt.Println("Succeed to verify certificate")
	return true
}
