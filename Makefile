QUIET := @

MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT := $(patsubst %/,%,$(dir $(MAKEFILE_PATH)))
export GOPATH = $(ROOT)

BIN := $(ROOT)/bin/maker-auth

SIGN_CERT := iPhone Developer: Tobias Blom (396WX5EMB8)

TLS_CERT := certs/server.pem
TLS_KEY := certs/server.key
TLS_SUBJ := "/C=SE/ST=E/L=Earth/O=Techne Development AB/OU=RnD/CN=localhost/emailAddress=tobias.blom@techne-dev.se"

.PHONY: run sign $(BIN) certs

run: sign
	$(QUIET)echo "Run!"; \
	exec $(BIN)

sign: $(BIN)
	$(QUIET)echo "Signing..."; \
	codesign -f -s "$(SIGN_CERT)" $(BIN)

$(BIN):
	$(QUIET)echo "Compiling..."; \
	go install techne-dev.se/maker-auth/...

certs: $(TLS_CERT) $(TLS_KEY)
$(TLS_CERT) $(TLS_KEY):
	mkdir -p $(dir $(TLS_CERT)); \
	openssl req -new -nodes -x509 -out $(TLS_CERT) -keyout $(TLS_KEY) -days 3650 -subj $(TLS_SUBJ)