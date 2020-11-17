NAME=kr_server
GOBUILD=go build --ldflags="-s -w" -v -x -a
GOFILES=

GENERATE_CODE_DIR=generate_code

$(shell protoc --go_out=. --go-grpc_out=. ./protos/issuecert.proto)
$(shell protoc --go_out=. ./protos/auth_message.proto)

all: linux-amd64 linux-armv6

linux-amd64:
	GOARCH=amd64 GOOS=linux $(GOBUILD) -o $(NAME)-$@ $(GOFILES)
linux-armv6:
	GOARCH=arm GOOS=linux GOARM=6 $(GOBUILD) -o $(NAME)-$@ $(GOFILES)
install:
	mkdir output
	cp $(NAME)-linux-amd64 output

clean:
	-rm -rf $(NAME)-linux-amd64
	-rm -rf $(NAME)-linux-armv6
	-rm -rf $(GENERATE_CODE_DIR)
	-rm -rf output
