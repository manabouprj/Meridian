.PHONY: install test lint demo serve doctor lock docker hcl
install: ; python -m pip install -r requirements-dev.txt
test:    ; python -m pytest -q
lint:    ; ruff check meridian tests
demo:    ; python -m meridian demo
serve:   ; python -m meridian serve
doctor:  ; python -m meridian doctor
lock:    ; pip-compile -q --strip-extras --no-emit-index-url --output-file requirements.txt requirements.in
docker:  ; docker build -t meridian:1.0.0 .
hcl:     ; python scripts/check_hcl.py
