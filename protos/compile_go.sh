#!/bin/bash

if [ -e "generate" ];then
    rm -rf generate
fi
protoc --go_out=. --go-grpc_out=. issuecert.proto
protoc --go_out=. auth_message.proto