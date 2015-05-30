package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type WebserviceHandler struct {
	ldap *LDAPHandler
}

type Response struct {
	Msg    string `json:"msg"`
	Status int64  `json:"status"`
}

type User struct {
	FirstName string `json:"firstName"`
	Surname   string `json:"surname"`
	Username  string `json:"username"`
	UID       int64  `json:"uid"`
	GID       int64  `json:"gid"`
	Gecos     string `json:"gecos"`
}

func NewWebserviceHandler() *WebserviceHandler {
	h := new(WebserviceHandler)
	h.ldap = new(LDAPHandler)
	return h
}

func (self *WebserviceHandler) listUsers(res http.ResponseWriter, req *http.Request) {
	log.Println("List users")

	_users, err := self.ldap.listUsers()
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	type _User struct {
		Username string `json:"username"`
		UID      int64  `json:"uid"`
		GID      int64  `json:"gid"`
	}

	users := make([]_User, len(_users))
	for i, user := range _users {
		users[i] = _User{user.Username, user.UID, user.GID}
	}

	res.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(res).Encode(users); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}

func (self *WebserviceHandler) createUser(res http.ResponseWriter, req *http.Request) {
	log.Println("Create user")

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	//	Parse input
	type Params struct {
		FirstName string
		Surname   string

		Username string
		Password string
	}

	params := Params{}

	err = json.Unmarshal(body, &params)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	if params.FirstName == "" || params.Surname == "" || params.Username == "" || params.Password == "" {
		http.Error(res, "Input error", http.StatusInternalServerError)
		return
	}

	// Create user in LDAP
	user := User{
		FirstName: params.FirstName,
		Surname:   params.Surname,
		Username:  params.Username,
	}

	if err := self.ldap.createNewUser(&user, params.Password); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.WriteHeader(http.StatusOK)
}

func (self *WebserviceHandler) getUser(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	username := vars["username"]

	log.Printf("Get user: %s\n", username)

	_user, err := self.ldap.getUser(username)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	type JSONUser struct {
		Gecos    string `json:"gecos"`
		Username string `json:"username"`
		UID      int64  `json:"uid"`
		GID      int64  `json:"gid"`
	}

	user := JSONUser{
		Username: _user.Username,
		UID:      _user.UID,
		GID:      _user.GID,
		Gecos:    _user.Gecos,
	}

	res.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(res).Encode(user); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}

func (self *WebserviceHandler) updateUser(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	username := vars["username"]

	log.Printf("Update user: %s\n", username)

	res.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(res).Encode(Response{"Not implemented yet", 99}); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}

func (self *WebserviceHandler) authenticate(res http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	//  Parse input
	type Params struct {
		Username, Password string
	}

	params := Params{}

	if err := json.Unmarshal(body, &params); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	// Validate input
	if params.Username == "" || params.Password == "" {
		http.Error(res, "Input error", http.StatusInternalServerError)
		return
	}

	// Authenticate
	if self.ldap.authenticateUser(params.Username, params.Password) {
		res.WriteHeader(http.StatusOK)
		return
	} else {
		// Password is invalid
		res.WriteHeader(http.StatusForbidden)
		return
	}
}
