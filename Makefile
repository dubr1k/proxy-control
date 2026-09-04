.PHONY: lab-test lab-prepare lab-start lab-reset lab-smoke lab-full lab-release lab-stop lab-clean

LAB = python3 scripts/lab/qemu_lab.py

lab-test:
	python3 -m unittest -v tests/lab/test_qemu_lab.py
	bash -n scripts/lab/guest-runner.sh
	shellcheck scripts/lab/guest-runner.sh

lab-prepare:
	$(LAB) prepare

lab-start:
	$(LAB) start --mode smoke

lab-reset:
	$(LAB) reset

lab-smoke:
	$(LAB) run --mode smoke --output lab-results

lab-full:
	$(LAB) run --mode full --output lab-results

# Release acceptance runs against one exact archive:
#   make lab-release RELEASE_ARCHIVE=dist/proxy-control-v2.0.0.tar.gz \
#     RELEASE_SHA256=<sha256> [LAB_ARCH=amd64|arm64] [LAB_SCENARIOS="audit plan"]
LAB_ARCH ?= amd64
LAB_SCENARIOS ?=
lab-release:
	@test -n "$(RELEASE_ARCHIVE)" || { echo "set RELEASE_ARCHIVE=<path>" >&2; exit 2; }
	@test -n "$(RELEASE_SHA256)" || { echo "set RELEASE_SHA256=<sha256>" >&2; exit 2; }
	$(LAB) run --mode release-$(LAB_ARCH) --output lab-results \
	  --release-archive $(RELEASE_ARCHIVE) --release-sha256 $(RELEASE_SHA256) \
	  $(foreach scenario,$(LAB_SCENARIOS),--scenario $(scenario))

lab-stop:
	$(LAB) stop

lab-clean:
	$(LAB) cleanup
