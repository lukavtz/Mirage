# syntax=docker/dockerfile:1
FROM node:22-alpine AS frontend
WORKDIR /web
ARG NPM_REGISTRY=https://registry.npmjs.org
COPY web/package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --prefer-offline --no-audit --no-fund --registry=${NPM_REGISTRY} --fetch-retries=10 --fetch-retry-maintimeout=30000 --fetch-retry-maxtimeout=120000
COPY web/ .
RUN npm run build

# Stage 2: build Go binaries (PostgreSQL-only, CGO-free)
FROM golang:1.26-alpine AS backend
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
COPY --from=frontend /web/dist ./cmd/panel/frontend/dist
RUN CGO_ENABLED=0 go build -o /panel ./cmd/panel \
    && CGO_ENABLED=0 go build -o /hashpw ./cmd/hashpw

# Stage 3: runtime — non-root
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S panel && adduser -S panel -G panel
WORKDIR /app
COPY --from=backend /panel .
COPY --from=backend /hashpw .
RUN mkdir -p data && chown -R panel:panel /app
USER panel
EXPOSE 8080
# /health is auth-free and returns 200 when the panel is up.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/health >/dev/null || exit 1
CMD ["./panel"]
