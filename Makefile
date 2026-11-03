.PHONY: setup validate unit kusto-up kusto-down test-kql check catalog

setup:
	python -m pip install -e '.[dev]'
	npm ci --prefix kql-check

validate:
	sdac validate

unit:
	pytest -q

kusto-up:
	docker run -d --rm --name sdac-kusto -p 8080:8080 -e ACCEPT_EULA=Y mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest

kusto-down:
	docker stop sdac-kusto

test-kql:
	sdac test --wait 300

catalog:
	sdac catalog

check: validate unit
