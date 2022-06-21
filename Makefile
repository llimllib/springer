bin/springerd: server/main.go
	go build -o bin/springerd ./server

bin/springer: client/main.go
	go build -o bin/springer ./client

# Use zig as the cc to cross-compile mattn/sqlite for linux
#
# working off https://zig.news/kristoff/building-sqlite-with-cgo-for-every-os-4cic
#
# this is basically magic
# 
# to run locally:
#   docker run -it -v $(pwd)/bin:/app ubuntu /app/springerd-linux
bin/springerd-linux: server/main.go
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC="zig cc -target x86_64-linux" CXX="zig cc -target x86_64-linux" go build -o bin/springerd-linux ./server
