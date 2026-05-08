# go-spiffe

## Run comformance tests

go build -o sdks/go-spiffe/go-spiffe sdks/go-spiffe/main.go 
go run cmd/suite/main.go run --cmd="sdks/go-spiffe/go-spiffe"