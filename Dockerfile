FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod .
COPY . .
RUN apk add --no-cache git
RUN go build -o /bin/scanropods ./cmd/server

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /bin/scanropods /bin/scanropods
# scanners are assumed to be preinstalled in the final image by other build steps or base image
EXPOSE 8080
USER 1000:1000
ENTRYPOINT ["/bin/scanropods"]
