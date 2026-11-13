FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /pepe ./cmd/pepe
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /pepe /pepe
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/pepe"]
CMD ["serve", "--listen", "0.0.0.0:8080", "--db", "/data/pepe.sqlite"]
