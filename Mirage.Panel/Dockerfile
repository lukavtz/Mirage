FROM node:24-alpine AS frontend
WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
RUN npm run build

FROM golang:1.25-alpine AS backend
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN rm -rf cmd/panel/frontend/dist && mkdir -p cmd/panel/frontend/dist
COPY --from=frontend /app/dist cmd/panel/frontend/dist
RUN cd cmd/panel && CGO_ENABLED=0 go build -o /eidos-panel .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=backend /eidos-panel /usr/bin/
RUN mkdir /data
VOLUME ["/data"]
EXPOSE 8080
ENV DB_PATH=/data/mirage.db
ENV PORT=8080
CMD ["eidos-panel"]
