# Repository check suite. Mirrors the repo-integrity job in .github/workflows/ci.yml.
.PHONY: check lint test install-deps

check: lint test

install-deps:
	python3 -m pip install -r requirements.txt

lint:
	ruff check .

test:
	python3 tools/check_public_hygiene.py
	python3 tools/check_repo_integrity.py --require-jsonschema
	python3 tools/check_permit_to_x_artifacts.py
	python3 test-vectors/action_classification_derivation/v1/reference_executor.py
	node test-vectors/permit_co_signature/v1/reference_verify.mjs
	node test-vectors/permit_co_signature/v2/reference_verify.mjs
