FROM docker.io/golang:bullseye@sha256:8d717e8a7fa8035f5cfdcdc86811ffd53b7bb17542f419f2a121c4c7533d29ee as builder
COPY . /app
WORKDIR /app
RUN GOOS=linux GOARCH=amd64 go build -o dist/

FROM gcr.io/distroless/static-debian11@sha256:8ad6f3ec70dad966479b9fb48da991138c72ba969859098ec689d1450c2e6c97
COPY --from=builder /app/dist/mkcert /bin/mkcert
USER 1001
CMD ["/bin/mkcert"]
EXPOSE 8080
