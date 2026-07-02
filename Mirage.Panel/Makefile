.PHONY: dev build test clean

dev:
	go run ./cmd/panel

build:
	cd web && npm run build
	rsync -a --delete frontend/dist/ cmd/panel/frontend/dist/
	go build -o bin/mirage-panel ./cmd/panel

test:
	go test ./... -v -count=1

clean:
	rm -rf bin/
	rm -f data/mirage.db data/mirage.db-*
