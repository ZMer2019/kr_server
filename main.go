package main

import (
	"context"
	"crypto/rsa"
	rd "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"google.golang.org/grpc"
	"io/ioutil"
	"kr_server/http_server"
	"log"
	"math/big"
	"math/rand"
	"net"
	"kr_server/generate_code/auth"
	"time"
)


func parseCert(path string)(*x509.Certificate, error){
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	http_server.SetRootCert(string(buf))
	p := &pem.Block{}
	p, buf = pem.Decode(buf)
	return x509.ParseCertificate(p.Bytes)
}
func ParseKey(path string)(*rsa.PrivateKey, error){
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	http_server.SetRootKey(string(buf))
	p, buf := pem.Decode(buf)
	return x509.ParsePKCS1PrivateKey(p.Bytes)
}
func parse(certPath, keyPath string)(*x509.Certificate, *rsa.PrivateKey, error){
	rootCertificate, err := parseCert(certPath)
	if err != nil {
		return nil, nil, err
	}
	rootPrivateKey, err := ParseKey(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return rootCertificate, rootPrivateKey, nil
}
const(
	CAType_root int32 = 0
	CAType_intermediate int32 = 1
	CAType_user int32 = 2
)
type CertInformation struct {
	Country 			[]string
	Organization		[]string
	OrganizationalUnit	[]string
	EmailAddress		[]string
	Province			[]string
	Locality			[]string
	CommonName			string
	Names				[]pkix.AttributeTypeAndValue
	ExtraInfo			string
	IpAddress			string
	DNSName				string
	CAType				int32
}
func (info CertInformation)Cert()*x509.Certificate{
	ret := &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63()),
		Subject: pkix.Name{
			Country: info.Country,
			Organization: info.Organization,
			OrganizationalUnit: info.OrganizationalUnit,
			Province: info.Province,
			CommonName: info.CommonName,
			Locality: info.Locality,
			ExtraNames: info.Names,
		},
		DNSNames: []string{info.DNSName},
		NotBefore: time.Now(),
		NotAfter: time.Now().AddDate(20,0,0),
		BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth ,x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign |x509.KeyUsageCRLSign,
		EmailAddresses: info.EmailAddress,
	}
	switch info.CAType {
	case CAType_root:
		ret.IsCA = true
	case CAType_intermediate:
		ret.IsCA = true
		ret.MaxPathLenZero = true
		ret.ExtraExtensions = []pkix.Extension{
			{
				Id: asn1.ObjectIdentifier([]int{2, 16, 3, 14}),
				Critical: false,
				Value: []byte(info.ExtraInfo),
			},
		}
	case CAType_user:
		ret.IsCA = false
	}
	return ret
}
func getPublicKey(publicKey string)(*rsa.PublicKey, error){
	key := []byte(publicKey)
	block,_:= pem.Decode(key)
	if block == nil{
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return pub, nil
}
func GenerateCert(rootCert *x509.Certificate,
	rootKey *rsa.PrivateKey,
	username, clientPublicKey string, caType int32)(string, error){
	certInfo := CertInformation{
		Country: []string{"CN"},
		Organization: []string{"test"},
		CAType: caType,
		OrganizationalUnit: []string{"RSAServer"},
		EmailAddress: []string{"test@test.com"},
		Locality: []string{"sz"},
		Province: []string{"gd"},
		CommonName: username,
		IpAddress: "",
		ExtraInfo: "test",
		DNSName: "test.oa.com",
	}
	clientPub, err := getPublicKey(clientPublicKey)
	if err != nil {
		return "", err
	}
	buf, err := x509.CreateCertificate(rd.Reader, certInfo.Cert(),rootCert,
		clientPub,rootKey)
	if err != nil {
		return "", nil
	}
	var b *pem.Block = &pem.Block{
		Bytes: buf,
		Type: "CERTIFICATE",
	}
	return string(pem.EncodeToMemory(b)),nil
}

type CAServer struct{
	auth.UnimplementedCAServerServer
}

func (s *CAServer)IssueCert(ctx context.Context, in *auth.IssueCertRequest)(*auth.IssueCertResponse, error){
	resp := new(auth.IssueCertResponse)
	fmt.Println(in.PublicKey)
	fmt.Println("public Key:===========\n", in.PublicKey)
	rootCert, rootKey, err := parse("./root.crt","./root.key")
	if err != nil{
		fmt.Println(err.Error())
		resp.Cert = "bad"
		return resp, nil
	}
	cert, err := GenerateCert(rootCert, rootKey,
		"ymx", in.PublicKey,CAType_intermediate)
	if err != nil {
		fmt.Println(err.Error())
		resp.Cert = "bad"
	}
	resp.Cert = cert

	block1, _ := pem.Decode([]byte(cert))
	var cert1* x509.Certificate
	cert1, _ = x509.ParseCertificate(block1.Bytes)
	rsaPublicKey := cert1.PublicKey.(*rsa.PublicKey)
	bytePublicKey,_ := x509.MarshalPKIXPublicKey(rsaPublicKey)
	pemPub := pem.Block{
		Type: "RSA PUBLIC KEY",
		Bytes: bytePublicKey,
	}
	fmt.Println("2222 public key:\n", string(pem.EncodeToMemory(&pemPub)))
	return resp, nil
}

func main() {
	// start http server
	go http_server.HttpServer()
	// start grpc server
	lis, err := net.Listen("tcp", ":9999")
	if err != nil {
		log.Fatal("failed to listen:%v", ":9999")
	}
	fmt.Println("listen: 0.0.0.0:9999")
	s := grpc.NewServer()
	auth.RegisterCAServerServer(s, &CAServer{})
	if err := s.Serve(lis); err != nil {
		log.Fatal("failed to server: %v", err)
	}
}