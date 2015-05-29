package main

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/hamano/golang-openldap"
)

const (
	srvAddr = ":8080"

	ldapSrv    = "ldap://ldap-server.local:389/"
	ldapBaseDN = "dc=techne-dev,dc=se"
	ouUsers    = "ou=Users"
	ouGroups   = "ou=Groups"

	ldapBind = "cn=root,dc=techne-dev,dc=se"
	ldapPwd  = "kalle"
)

type WebserviceHandler struct {
	ldap *LDAPHandler
}

type LDAPHandler struct {
	ldap *openldap.Ldap
}

func main() {

	handler := new(WebserviceHandler)
	handler.ldap = new(LDAPHandler)

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

		log.Printf("Starting server on %s", srvAddr)
		if err := http.ListenAndServe(srvAddr, nil); err != nil {
			log.Panicln(err)
		}
	}
}

//
//  WebService
//
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
}

func (handler *WebserviceHandler) listUsers(res http.ResponseWriter, req *http.Request) {
	log.Println("List users")

	_users, err := handler.ldap.listUsers()
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

	if err := json.NewEncoder(res).Encode(users); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}

func (handler *WebserviceHandler) createUser(res http.ResponseWriter, req *http.Request) {
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

	if err := handler.ldap.createNewUser(&user, params.Password); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(res).Encode(Response{"OK", 0}); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}

func (handler *WebserviceHandler) getUser(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	username := vars["username"]

	log.Printf("Get user: %s\n", username)

	user, err := handler.ldap.getUser(username)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(res).Encode(user); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}

func (handler *WebserviceHandler) updateUser(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	username := vars["username"]

	log.Printf("Update user: %s\n", username)

	if err := json.NewEncoder(res).Encode(Response{"Not implemented yet", 99}); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}

func (handler *WebserviceHandler) authenticate(res http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	type Params struct {
		Username, Password string
	}

	params := Params{}

	err = json.Unmarshal(body, &params)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	if params.Username == "" || params.Password == "" {
		http.Error(res, "Input error", http.StatusInternalServerError)
		return
	}
	if !handler.ldap.authenticateUser(params.Username, params.Password) {
		// Password is invalid
		res.WriteHeader(http.StatusForbidden)
		return
	}

	// Password is valid
	if err := json.NewEncoder(res).Encode(Response{"OK", 0}); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}

//
//  LDAP stuff
//
func (handler *LDAPHandler) connect() error {
	var err error
	handler.ldap, err = openldap.Initialize(ldapSrv)
	if err != nil {
		log.Println(err)
		return err
	}

	handler.ldap.SetOption(openldap.LDAP_OPT_PROTOCOL_VERSION, openldap.LDAP_VERSION3)

	return nil
}

func (handler *LDAPHandler) close() {
	handler.ldap.Close()
}

func (handler *LDAPHandler) getUsersDN() string {
	return fmt.Sprintf("ou=Users,%s", ldapBaseDN)
}

func (handler *LDAPHandler) getGroupsDN() string {
	return fmt.Sprintf("ou=Users,%s", ldapBaseDN)
}

func (handler *LDAPHandler) getUIDNextDN() string {
	return fmt.Sprintf("cn=uidNext,%s", ldapBaseDN)
}

//
//  User handling
//
func (ldap *LDAPHandler) listUsers() ([]User, error) {
	var err error

	if err = ldap.connect(); err != nil {
		return nil, err
	}

	defer ldap.close()

	var ldapRes *openldap.LdapSearchResult
	ldapRes, err = ldap.ldap.SearchAll(
		ldap.getUsersDN(),
		openldap.LDAP_SCOPE_SUBTREE,
		"objectClass=posixAccount",
		[]string{"uid", "cn", "uidnumber", "gidnumber"})
	if err != nil {
		return nil, err
	}

	users := make([]User, 0)

	for _, ldapEntry := range ldapRes.Entries() {
		user := User{}

		for _, attr := range ldapEntry.Attributes() {
			switch attr.Name() {
			case "uid":
				user.Username = attr.Values()[0]
			case "uidNumber":
				if user.UID, err = strconv.ParseInt(attr.Values()[0], 10, 64); err != nil {
					return nil, errors.New("Search result error")
				}
			case "gidNumber":
				if user.GID, err = strconv.ParseInt(attr.Values()[0], 10, 64); err != nil {
					return nil, errors.New("Search result error")
				}
			}
		}

		users = append(users, user)
	}

	return users, nil
}

func (self *LDAPHandler) createNewUser(user *User, password string) error {
	log.Printf("Create user: %s with password %s\n", user, password)

	if err := self.isAvailable(user.FirstName, user.Surname, user.Username); err != nil {
		return err
	}

	var err error

	fullName := fmt.Sprintf("%s %s", user.FirstName, user.Surname)
	ssha := generatePassword(password, nil)
	homeDir := fmt.Sprintf("/home/%s", user.Username)

	_UID, err := self.getNextUID()
	if err != nil {
		return err
	}
	UID := strconv.FormatUint(_UID, 10)

	_shadowLastChanged := time.Now().Unix() / 86400
	shadowLastChanged := fmt.Sprintf("%d", _shadowLastChanged)

	dnUser := fmt.Sprintf("uid=%s,%s", user.Username, self.getUsersDN())
	attrsUser := map[string][]string{
		"objectClass":      []string{"top", "person", "posixAccount", "shadowAccount"},
		"cn":               []string{user.Username},
		"sn":               []string{user.Surname},
		"uid":              []string{user.Username},
		"userPassword":     []string{ssha},
		"uidNumber":        []string{UID},
		"gidNumber":        []string{UID},
		"homeDirectory":    []string{homeDir},
		"gecos":            []string{fullName},
		"loginShell":       []string{"/bin/bash"},
		"shadowLastChange": []string{shadowLastChanged},
		"shadowMin":        []string{"0"},
		"shadowMax":        []string{"999999"},
		"shadowWarning":    []string{"7"},
		"shadowInactive":   []string{"-1"},
		"shadowExpire":     []string{"-1"},
		"shadowFlag":       []string{"0"},
	}

	dnGroup := fmt.Sprintf("cn=%s,%s", user.Username, self.getGroupsDN())
	attrsGroup := map[string][]string{
		"objectclass": []string{"top", "posixGroup"},
		"cn":          []string{user.Username},
		"gidnumber":   []string{UID},
		"memberuid":   []string{user.Username},
	}

	if err = self.connect(); err != nil {
		return err
	}

	defer self.close()

	if err := self.ldap.Bind(ldapBind, ldapPwd); err != nil {
		return err
	}

	if err := self.ldap.Add(dnUser, attrsUser); err != nil {
		return err
	}

	if err := self.ldap.Add(dnGroup, attrsGroup); err != nil {
		self.ldap.Delete(dnUser)
		return err
	}

	return nil
}

func (self *LDAPHandler) getUser(username string) (*User, error) {
	var err error

	if err = self.connect(); err != nil {
		return nil, err
	}

	defer self.close()

	var ldapRes *openldap.LdapSearchResult
	ldapRes, err = self.ldap.SearchAll(
		self.getUsersDN(),
		openldap.LDAP_SCOPE_SUBTREE,
		fmt.Sprintf("(&(objectClass=posixAccount)(uid=%s))", username),
		[]string{"uid", "cn", "uidnumber", "gidnumber"})
	if err != nil {
		return nil, err
	}

	if ldapRes.Count() != 1 {
		return nil, errors.New("Search result error")
	}

	ldapEntry := ldapRes.Entries()[0]

	user := new(User)

	for _, attr := range ldapEntry.Attributes() {
		switch attr.Name() {
		case "uid":
			user.Username = attr.Values()[0]
		case "uidNumber":
			if user.UID, err = strconv.ParseInt(attr.Values()[0], 10, 64); err != nil {
				return nil, errors.New("Search result error")
			}
		case "gidNumber":
			if user.GID, err = strconv.ParseInt(attr.Values()[0], 10, 64); err != nil {
				return nil, errors.New("Search result error")
			}
		}
	}

	return user, nil
}

func (self *LDAPHandler) authenticateUser(username, password string) bool {
	var err error

	if err = self.connect(); err != nil {
		return false
	}

	defer self.close()

	/*
		dn := fmt.Sprintf("uid=%s,%s", username, self.getUsersDN())
		if err := self.ldap.Bind(dn, password); err == nil {
			return true
		}

		return false
	*/

	var ldapRes *openldap.LdapSearchResult
	ldapRes, err = self.ldap.SearchAll(
		self.getUsersDN(),
		openldap.LDAP_SCOPE_SUBTREE,
		fmt.Sprintf("(&(objectClass=posixAccount)(uid=%s))", username),
		[]string{"userPassword"})
	if err != nil {
		return false
	}

	if ldapRes.Count() != 1 {
		return false
	}

	ldapEntry := ldapRes.Entries()[0]

	ssha, err := ldapEntry.GetOneValueByName("userPassword")
	if err != nil {
		return false
	}

	return validatePassword(password, ssha)
}

func (self *LDAPHandler) disableUser(username string) error {
	return errors.New("Not implemented yet")
}

func (self *LDAPHandler) isAvailable(fn, sn, username string) error {
	// Check username
	if _, err := self.getUser(username); err == nil {
		return errors.New("Username not available")
	}

	// Check group
	if avail := self.isGroupAvailable(username); !avail {
		return errors.New("Group name not available")
	}

	return nil
}

func (self *LDAPHandler) isGroupAvailable(groupname string) bool {
	if err := self.connect(); err != nil {
		return false
	}

	defer self.close()

	ldapRes, err := self.ldap.SearchAll(
		self.getGroupsDN(),
		openldap.LDAP_SCOPE_SUBTREE,
		fmt.Sprintf("(&(objectClass=posixGroup)(cn=%s))", groupname),
		[]string{})
	if err != nil {
		return false
	}

	return ldapRes.Count() == 0
}

func (self *LDAPHandler) getNextUID() (uint64, error) {
	if err := self.connect(); err != nil {
		return 0, err
	}

	defer self.close()

	if err := self.ldap.Bind(ldapBind, ldapPwd); err != nil {
		return 0, err
	}

	// Try to fetch uidNext, and increment it. If fail, retry a bit later
	for i := 0; i < 10; i++ {
		nextUID, errFetch := self._fetchNextUID(self.ldap)
		if errFetch != nil {
			log.Printf("Error fetching uidNext: %s\n", errFetch)
		} else {
			errInc := self._incrementNextUID(self.ldap, nextUID)
			if errInc != nil {
				log.Printf("Error incrementing uidNext: %s", errInc)
			} else {
				return nextUID, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	return 0, errors.New("Unable to get next UID")
}

func (self *LDAPHandler) _fetchNextUID(ldap *openldap.Ldap) (uint64, error) {
	ldapRes, err := ldap.SearchAll(
		ldapBaseDN,
		openldap.LDAP_SCOPE_ONELEVEL,
		"(objectClass=uidNext)",
		[]string{"uidNumber"})
	if err != nil {
		return 0, err
	}

	if ldapRes.Count() != 1 {
		return 0, errors.New("Unable to fetch next UID")
	}

	_nextUID, err := ldapRes.Entries()[0].GetOneValueByName("uidNumber")
	if err != nil {
		return 0, err
	}

	nextUID, err := strconv.ParseUint(_nextUID, 10, 64)
	if err != nil {
		return 0, err
	}

	return nextUID, err
}

func (self *LDAPHandler) _incrementNextUID(ldap *openldap.Ldap, currentUID uint64) error {
	_currentUID := strconv.FormatUint(currentUID, 10)
	_nextUID := strconv.FormatUint(currentUID+1, 10)

	attrs := map[string][]string{
		"uidNumber": []string{_currentUID},
	}

	if err := ldap.ModifyDel(self.getUIDNextDN(), attrs); err != nil {
		return err
	}

	attrsAdd := map[string][]string{
		"uidNumber": []string{_nextUID},
	}

	if err := ldap.ModifyAdd(self.getUIDNextDN(), attrsAdd); err != nil {
		return err
	}

	return nil
}

//
//  Passwords
//
func validatePassword(password, hashWithPrefix string) bool {
	hash_b64 := strings.TrimLeft(hashWithPrefix, "{SSHA}")
	hash, _ := base64.StdEncoding.DecodeString(hash_b64)

	bytes := []byte(hash)

	digest := bytes[:20]
	salt := bytes[20:]

	new_hash := generateHash(password, salt)

	return subtle.ConstantTimeCompare(digest, new_hash) == 1
}

func generatePassword(password string, salt []byte) string {
	if salt == nil {
		salt = make([]byte, 4)
		rand.Read(salt)
	}

	hash := generateHash(password, salt)
	return fmt.Sprintf("{SSHA}%s", base64.StdEncoding.EncodeToString(append(hash, salt...)))
}

func generateHash(password string, salt []byte) []byte {
	h := sha1.New()
	h.Write(append([]byte(password), salt...))
	return h.Sum(nil)
}
