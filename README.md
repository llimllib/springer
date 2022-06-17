# A testing Spring83 server

Implementing some of [this very draft spec](https://github.com/robinsloan/spring-83-spec/blob/main/draft-20220609.md)

# To test

## run the server

If you have [modd](https://github.com/cortesi/modd) installed, run `modd`. Alternatively, `go run server/main.go`

## run the client

On first run, the client will generate a keypair for you according to the spring83 spec, and store it in `~/.config/spring83/key.pub` and `~/.config/spring83/key.priv`.

This key has to meet a certain specification, so it may take up to a half hour to generate on the first run. The code to generate it is totally unoptimized and can probably be sped up, if you want to be the one to do that, awesome.

`echo "testing" | go run client/main.go`

## view the content

go to http://localhost:8000 while the server is running
