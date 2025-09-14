FROM docker.io/library/golang:1.25.0-alpine3.22 AS builder

WORKDIR /go/src/app

COPY go.mod go.sum ./
RUN go mod download \
    && go install github.com/mavolin/hashets/cmd/hashets@v1.3.0

COPY . .
RUN go generate ./... \
    && go build \
      -ldflags '-s -w' \
      -o oidc-tester-app .

FROM docker.io/library/alpine:3.22.1

RUN apk --no-cache add ca-certificates tzdata bash

WORKDIR /app

COPY --from=builder /go/src/app/oidc-tester-app oidc-tester-app

ENV PATH="${PATH}:/app"

CMD ["oidc-tester-app"]
