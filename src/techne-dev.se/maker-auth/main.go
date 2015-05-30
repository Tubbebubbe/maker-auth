package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

var (
	srvAddr = ":8080"

	ldapSrv    = "ldap://ldap-server.local:389/"
	ldapBaseDN = "dc=techne-dev,dc=se"

	ldapRootDN  = "cn=root,dc=techne-dev,dc=se"
	ldapRootPwd = "kalle"

	tlsOn   = false
	tlsCert = "certs/server.pem"
	tlsKey  = "certs/server.key"
)

func init() {
	flag.StringVar(&srvAddr, "addr", srvAddr, "Address to serve")

	flag.StringVar(&ldapSrv, "LDAP", ldapSrv, "LDAP server address")
	flag.StringVar(&ldapBaseDN, "LDAPBaseDN", ldapBaseDN, "LDAP base DN")
	flag.StringVar(&ldapRootDN, "LDAPRootDN", ldapRootDN, "LDAP admin user")
	flag.StringVar(&ldapRootPwd, "LDAPRootPwd", ldapRootPwd, "LDAP admin user password")

	flag.BoolVar(&tlsOn, "tls", tlsOn, "Web server uses TLS")
	flag.StringVar(&tlsCert, "tlsCert", tlsCert, "TLS certificate")
	flag.StringVar(&tlsKey, "tlsKey", tlsKey, "TLS private key")

	flag.Parse()
}

func main() {
	handler := NewWebserviceHandler()
	handler.ldap = NewLDAPHandler(ldapSrv, ldapBaseDN, ldapRootDN, ldapRootPwd)

	//
	//  Set up router
	//
	api := mux.NewRouter().StrictSlash(true).PathPrefix("/api").Subrouter()

	api.HandleFunc("/users", handler.listUsers).Methods("GET")
	api.HandleFunc("/users", handler.createUser).Methods("POST")
	api.HandleFunc("/users/{username}", handler.getUser).Methods("GET")
	api.HandleFunc("/users/{username}", handler.updateUser).Methods("PUT")

	api.HandleFunc("/authenticate", handler.authenticate).Methods("POST")

	http.Handle("/api/", api)

	//
	// Serve
	//
	for {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Caught panic while serving request: %v", r)
			}
		}()

		if tlsOn {
			log.Printf("Starting server on %s (TLS)", srvAddr)
			if err := http.ListenAndServeTLS(srvAddr, tlsCert, tlsKey, nil); err != nil {
				log.Panicln(err)
			}
		} else {
			log.Printf("Starting server on %s", srvAddr)
			if err := http.ListenAndServe(srvAddr, nil); err != nil {
				log.Panicln(err)
			}
		}

	}
}
