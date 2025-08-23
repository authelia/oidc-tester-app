FROM golang:1.25.0-alpine3.22 AS builder

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...
RUN go build -ldflags '-s -w' -o oidc-tester-app *.go

FROM alpine:3.22.1

RUN apk --no-cache add ca-certificates tzdata bash

WORKDIR /app

COPY --from=builder /go/src/app/oidc-tester-app oidc-tester-app

ENV PATH="${PATH}:/app"

CMD ["oidc-tester-app"]
