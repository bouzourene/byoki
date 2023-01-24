#!/bin/bash

env GOOS=darwin GOARCH=arm64 go build -o build/byoki-darwin-arm64
env GOOS=linux GOARCH=amd64 go build -o build/byoki-linux-amd64
env GOOS=windows GOARCH=arm64 go build -o build/byoki-windows-amd64