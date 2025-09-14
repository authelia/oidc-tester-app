# oidc-tester-app

oidc-tester-app is an OIDC client used for testing the OIDC API provided by Authelia

## Building

This project uses [hashets](https://github.com/mavolin/hashets) to generate cache-busting
asset URLs. Install it with `go install github.com/mavolin/hashets/cmd/hashets@v1.3.0` prior
to compilation.

```
go generate ./...
go build \
    -ldflags '-s -w' \
    -o oidc-tester-app .
```

## License

This software is licensed under [MIT](./LICENSE.md).
