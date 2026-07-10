.PHONY: dev run update lookup build test lint fmt docker deploy logs

# Build cache hors de l'arbre source (utile si le repo est sur un dossier
# synchronisé : évite le churn et la corruption du cache).
export CARGO_TARGET_DIR ?= $(HOME)/.cache/indic-target

IP ?= 1.1.1.1

## Récupère les datasets puis lance le serveur (dev)
dev: update run

## Lance l'API + le front (http://127.0.0.1:8080)
run:
	cargo run --release -- serve

## Télécharge / rafraîchit les datasets dans ./data
update:
	cargo run --release -- update

## Enrichit une IP : make lookup IP=8.8.8.8
lookup:
	cargo run --release -- lookup $(IP)

build:
	cargo build --release

test:
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

## Build l'image (amd64). Pour l'Oracle ARM : ajouter --platform linux/arm64
docker:
	docker build -t indic:latest .

VPS ?= your-vps-host

## Déploie sur le VPS (rsync du code + rebuild du container)
deploy:
	rsync -az --delete --exclude target --exclude data --exclude .git \
	  --exclude .claude --exclude .DS_Store --exclude .env -e ssh ./ $(VPS):~/indic/
	ssh $(VPS) 'cd ~/indic && docker compose up -d --build --force-recreate'

## Suit les logs du container sur le VPS
logs:
	ssh $(VPS) 'cd ~/indic && docker compose logs -f --tail=50'
