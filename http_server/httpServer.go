package http_server

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/mux"
	"kr_server/cert"
	"kr_server/generate_code/auth"
	"math/big"
	"net/http"
	"os"
	"time"
)

var (
	rootCert string
	rootKey string
)

func SetRootCert(cert string){
	fmt.Println(rootCert)
	rootCert = cert
}
func SetRootKey(key string){
	rootKey = key
}
func ValidateHandler(w http.ResponseWriter, r *http.Request){
	http.Redirect(w, r, "http://127.0.0.1:52018/auth?oriurl=http://test.oa.com:9090/auth", http.StatusFound)
}
type ECDSASignature struct {
	R, S *big.Int
}
func AuthHandler(w http.ResponseWriter,r *http.Request){
	signBase64Str := r.URL.Query().Get("sign")
	fmt.Println("signBase64Str\n", signBase64Str);
	signByte, _ := base64.StdEncoding.DecodeString(signBase64Str)
	fmt.Println("signatureBase64:\n",string(signByte))
	certBase64Str := r.URL.Query().Get("cert")
	certByte, _ := base64.StdEncoding.DecodeString(certBase64Str)
	fmt.Println(string(certByte))

	authInfoBase64Str := r.URL.Query().Get("authInfo")
	strByte, err := base64.StdEncoding.DecodeString(authInfoBase64Str)
	if err != nil {
		fmt.Errorf("base64 decode error:", err.Error())
		fmt.Fprintf(w,err.Error())
		return
	}
	fmt.Println("str:", string(strByte))
	var info auth.AgentAuthInfo
	proto.Unmarshal(strByte, &info)
	fmt.Printf("%v", info)

	bret := cert.Verify(rootCert, string(certByte))
	if !bret {
		fmt.Println("verify cert error")
	}
	block, _ := pem.Decode(certByte)
	var cert* x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)


	signature, _ := base64.StdEncoding.DecodeString(string(signByte))


	h := sha256.New()
	h.Write(strByte)
	msgHashSum := h.Sum(nil)
	err = rsa.VerifyPSS(rsaPublicKey,crypto.SHA256,msgHashSum, signature, nil)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("Verify rsa sign succeed")
}

func HttpServer(){
	muxR := mux.NewRouter()

	muxR.HandleFunc("/auth", AuthHandler)
	muxR.HandleFunc("/validate", ValidateHandler)
	server := http.Server{
		Addr: ":9090",
		ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler: muxR,
	}
	err := server.ListenAndServe()
	if err != nil {
		fmt.Errorf("%v", err.Error())
		os.Exit(1)
	}
}
