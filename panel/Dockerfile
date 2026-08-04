# Stage 1: build frontend (context = panel/)
FROM node:22-alpine AS frontend
WORKDIR /web
COPY web/package*.json ./
RUN npm ci --registry=https://registry.npmjs.org --fetch-retries=5 --fetch-retry-mintimeout=20000
COPY web/ .
RUN npm run build

# Stage 2: build Go binary (CGO-free, modernc/sqlite / pgx)
FROM golang:1.25-alpine AS backend
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
