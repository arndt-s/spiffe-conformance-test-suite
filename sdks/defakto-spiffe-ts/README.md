# defakto-spiffe-ts

## Build

```bash
npm install
npm run build
```

## Run conformance tests

```bash
npm run build
go run cmd/suite/main.go run --cmd="node" --args="sdks/defakto-spiffe-ts/dist/index.js"
```
