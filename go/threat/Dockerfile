# ======================================================================
# Stage 1: Prepare
FROM hub.viettelcybersecurity.com/vti/golang:1.23 as builder
WORKDIR /app

ARG GITLAB_USERNAME
ARG GITLAB_TOKEN
ENV GO111MODULE=on
ENV GOPRIVATE=gitlab.viettelcyber.com
ENV GOPROXY=https://proxy.golang.org
ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0

# Login Gitlab
RUN git config --global credential.helper store
RUN echo https://${GITLAB_USERNAME}:${GITLAB_TOKEN}@${GOPRIVATE} > ~/.git-credentials
# Build
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN go build -ldflags="-w -s" -o ws-threat

# ======================================================================
# Stage 2: Build
FROM hub.viettelcybersecurity.com/vti/alpine:3.14

WORKDIR /app
RUN addgroup -S ubuntu && adduser -S ubuntu -G ubuntu

RUN mkdir /app/temp/ /app/static/
COPY --from=builder /app/ws-threat /app/
COPY locales /app/locales/
# Copy ...

RUN chown -R ubuntu /app
USER ubuntu

ENTRYPOINT ["/app/ws-threat", "--config", "/app/config.yaml"]
