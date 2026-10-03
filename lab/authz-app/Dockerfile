FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o authz-app ./cmd/authz-app

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/authz-app .
EXPOSE 8080
CMD ["./authz-app"]
