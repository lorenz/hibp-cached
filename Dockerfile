FROM golang:1
ENV GO111MODULE on
ENV CGO_ENABLED 0
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build --ldflags="-w -s" -mod=readonly

FROM gcr.io/distroless/static-debian11:latest
COPY --from=0 /build/hibp-cached /
ENTRYPOINT ["/hibp-cached"]
