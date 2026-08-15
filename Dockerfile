# syntax=docker/dockerfile:1
ARG GO_BASE=docker.m.daocloud.io/library/golang:1.26.3-bookworm
ARG ALPINE_BASE=docker.m.daocloud.io/library/alpine:3.20

FROM ${GO_BASE} AS builder
ENV GOTOOLCHAIN=local
ENV CGO_ENABLED=0
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/task014-jwt .

FROM ${ALPINE_BASE}
WORKDIR /app
COPY --from=builder /out/task014-jwt /app/task014-jwt
EXPOSE 8080
ENTRYPOINT ["/app/task014-jwt"]
CMD ["server", "--addr", ":8080"]
