FROM golang:1.16

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...
RUN go build -o oidc-tester-app *.go

CMD ["oidc-tester-app"]
