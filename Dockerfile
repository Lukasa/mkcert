FROM docker.io/golang:1.23 as builder
COPY . /app
WORKDIR /app
RUN go test ./...
RUN GOOS=linux GOARCH=amd64 go build -o dist/

FROM gcr.io/distroless/static-debian12:latest
COPY --from=builder /app/dist/mkcert /bin/mkcert
USER 1001
CMD ["/bin/mkcert"]
EXPOSE 8080
