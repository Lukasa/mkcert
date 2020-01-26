FROM golang

ADD . /go/src/github.com/Lukasa/mkcert

RUN go install github.com/Lukasa/mkcert

ENTRYPOINT /go/bin/mkcert

EXPOSE 8080
