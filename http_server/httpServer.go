package http_server

import (
	"encoding/base64"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/mux"
	"kr_server/generate_code/auth"
	"net/http"
	"os"
	"time"
)

func ValidateHandler(w http.ResponseWriter, r *http.Request){
	http.Redirect(w, r, "http://127.0.0.1:52018/auth?oriurl=http://test.oa.com:9090/auth", http.StatusFound)
}

func AuthHandler(w http.ResponseWriter,r *http.Request){
	signBase64Str := r.URL.Query().Get("sign")
	signByte, _ := base64.StdEncoding.DecodeString(signBase64Str)
	fmt.Println(string(signByte))
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
