FROM --platform=${BUILDPLATFORM} golang:1.26.2-alpine3.22 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /go/src/app
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags '-s -w' -o oidc-tester-app *.go

FROM alpine:3.23.3

RUN apk --no-cache add ca-certificates tzdata bash

WORKDIR /app

COPY --from=builder /go/src/app/oidc-tester-app oidc-tester-app

ENV PATH="${PATH}:/app"

CMD ["oidc-tester-app"]
