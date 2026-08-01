# Stage 1: build frontend
FROM node:20-alpine AS frontend
WORKDIR /web
COPY panel/web/package*.json ./
RUN npm ci
COPY panel/web/ .
RUN npm run build

# Stage 2: build Go binary (CGO-free, modernc/sqlite)
FROM golang:1.25-alpine AS backend
WORKDIR /app
COPY panel/go.* ./
RUN go mod download
COPY panel/ .
COPY --from=frontend /web/dist ./cmd/panel/frontend/dist
RUN CGO_ENABLED=0 go build -o /panel ./cmd/panel

# Stage 3: runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=backend /panel .
RUN mkdir -p data
EXPOSE 8080
CMD ["./panel"]
