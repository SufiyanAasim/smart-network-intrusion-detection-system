.PHONY: install run api test lint train docker-build docker-config docker-up docker-api docker-capture

install:
	pip install -r requirements-dev.txt

run:
	streamlit run src/nids/app.py

api:
	python src/nids/api.py

test:
	pytest -q

lint:
	ruff check src tests scripts
	yamllint -c .yamllint.yml .github/workflows .github/dependabot.yml docker-compose.yml render.yaml config/features.yaml

train:
	python scripts/train_models.py

docker-build:
	docker build --pull -t nids:10.0.0 -t nids:latest .

docker-config:
	docker compose --profile api --profile capture config --quiet

docker-up:
	docker compose up --build

docker-api:
	docker compose --profile api up --build

docker-capture:
	docker compose --profile capture up nids-capture --build
