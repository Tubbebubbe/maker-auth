QUIET := @

MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT := $(patsubst %/,%,$(dir $(MAKEFILE_PATH)))
export GOPATH = $(ROOT)

BIN := $(ROOT)/bin/maker-auth

CERT := iPhone Developer: Tobias Blom (396WX5EMB8)

.PHONY: run sign $(BIN)

run: sign
	$(QUIET)echo "Run!"; \
	exec $(BIN)

sign: $(BIN)
	$(QUIET)echo "Signing..."; \
	codesign -f -s "$(CERT)" $(BIN)

$(BIN):
	$(QUIET)echo "Compiling..."; \
	go install techne-dev.se/maker-auth/...
