CLOUD_INIT_DIR ?= $(HOME)/git/cloud-init

.PHONY: build test test-conformance

build:
	go build ./...

test:
	go test ./...

# Run the EC2 IMDS conformance suite.
#
# The suite starts the imds-conformance-server binary (built on demand by the
# pytest fixture in conftest.py), points cloud-init's DataSourceEc2 at it, and
# asserts that metadata is crawled and parsed correctly.
#
# The test is expected to FAIL until the EC2-compatible HTTP handler is
# implemented — that's the intended TDD red bar.
test-conformance:
	cd tests/conformance && \
	  PYTHONPATH=$(CLOUD_INIT_DIR) \
	  uv run --project . pytest -v --tb=short .
