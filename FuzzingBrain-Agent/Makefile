# Thin wrapper over setup.sh, for people who type `make` first.
.PHONY: setup test check clean

setup:                       ## create .venv and install the pinned dependencies
	./setup.sh

test: .venv/bin/python       ## run the test suite
	.venv/bin/python -m pytest tests -q

check: .venv/bin/python      ## prove a run can start without any external setup
	.venv/bin/python -c "import litellm, typer, jinja2, pydantic; print('deps ok')"
	.venv/bin/python -m fb_agent --help >/dev/null && echo "entry point ok"

.venv/bin/python:
	./setup.sh

clean:                       ## remove the virtualenv
	rm -rf .venv
