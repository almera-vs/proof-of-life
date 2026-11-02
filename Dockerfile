FROM golang:1.27 AS build
ARG VERSION=0.1.0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/almera-vs/proof-of-life/internal/obs.Version=${VERSION}" \
    -o /pol ./cmd/pol

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /pol /usr/local/bin/pol
ENTRYPOINT ["/usr/local/bin/pol"]
