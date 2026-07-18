.PHONY: install run api test lint train docker-build docker-up

install:
	pip install -r requirements-dev.txt

run:
	streamlit run src/nids/app.py

api:
	PYTHONPATH=src python -m nids.api

test:
	pytest -q

lint:
	ruff check src tests scripts

train:
	python scripts/train_models.py

docker-build:
	docker build -t nids:latest .

docker-up:
	docker compose up --build
