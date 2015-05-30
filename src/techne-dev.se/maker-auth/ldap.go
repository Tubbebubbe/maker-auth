package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/hamano/golang-openldap"
)

type LDAPHandler struct {
	ldap *openldap.Ldap

	server string
	baseDN string

	adminDN  string
	adminPwd string
}

func NewLDAPHandler(server, baseDN, adminDN, adminPwd string) *LDAPHandler {
	h := new(LDAPHandler)

	h.ldap = new(openldap.Ldap)

	h.server = server
	h.baseDN = baseDN

	h.adminDN = adminDN
	h.adminPwd = adminPwd

	return h
}

func (h *LDAPHandler) connect() error {
	var err error
	h.ldap, err = openldap.Initialize(h.server)
	if err != nil {
		log.Println(err)
		return err
	}

	h.ldap.SetOption(openldap.LDAP_OPT_PROTOCOL_VERSION, openldap.LDAP_VERSION3)

	return nil
}

func (h *LDAPHandler) close() {
	h.ldap.Close()
}

func (h *LDAPHandler) getUsersDN() string {
	return fmt.Sprintf("ou=Users,%s", h.baseDN)
}

func (h *LDAPHandler) getGroupsDN() string {
	return fmt.Sprintf("ou=Groups,%s", h.baseDN)
}

func (h *LDAPHandler) getUIDNextDN() string {
	return fmt.Sprintf("cn=uidNext,%s", h.baseDN)
}

//
//  User handling
//
func (h *LDAPHandler) listUsers() ([]User, error) {
	var err error

	if err = h.connect(); err != nil {
		return nil, err
	}

	defer h.close()

	var ldapRes *openldap.LdapSearchResult
	ldapRes, err = h.ldap.SearchAll(
		h.getUsersDN(),
		openldap.LDAP_SCOPE_SUBTREE,
		"objectClass=posixAccount",
		[]string{"uid", "uidnumber", "gidnumber"})
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

func (h *LDAPHandler) createNewUser(user *User, password string) error {
	log.Printf("Create user: %s with password %s\n", user, password)

	if err := h.isAvailable(user.FirstName, user.Surname, user.Username); err != nil {
		return err
	}

	var err error

	fullName := fmt.Sprintf("%s %s", user.FirstName, user.Surname)
	ssha := generatePassword(password, nil)
	homeDir := fmt.Sprintf("/home/%s", user.Username)

	_UID, err := h.getNextUID()
	if err != nil {
		return err
	}
	UID := strconv.FormatUint(_UID, 10)

	shadowLastChanged := fmt.Sprintf("%d", time.Now().Unix()/86400)

	dnUser := fmt.Sprintf("uid=%s,%s", user.Username, h.getUsersDN())
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

	dnGroup := fmt.Sprintf("cn=%s,%s", user.Username, h.getGroupsDN())
	attrsGroup := map[string][]string{
		"objectclass": []string{"top", "posixGroup"},
		"cn":          []string{user.Username},
		"gidnumber":   []string{UID},
		"memberuid":   []string{user.Username},
	}

	if err = h.connect(); err != nil {
		return err
	}

	defer h.close()

	if err := h.ldap.Bind(h.adminDN, h.adminPwd); err != nil {
		return err
	}

	if err := h.ldap.Add(dnUser, attrsUser); err != nil {
		return err
	}

	if err := h.ldap.Add(dnGroup, attrsGroup); err != nil {
		h.ldap.Delete(dnUser)
		return err
	}

	return nil
}

func (h *LDAPHandler) getUser(username string) (*User, error) {
	var err error

	if err = h.connect(); err != nil {
		return nil, err
	}

	defer h.close()

	var ldapRes *openldap.LdapSearchResult
	ldapRes, err = h.ldap.SearchAll(
		h.getUsersDN(),
		openldap.LDAP_SCOPE_SUBTREE,
		fmt.Sprintf("(&(objectClass=posixAccount)(uid=%s))", username),
		[]string{"uid", "cn", "uidnumber", "gidnumber", "gecos"})
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
		case "gecos":
			user.Gecos = attr.Values()[0]
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

func (h *LDAPHandler) authenticateUser(username, password string) bool {
	var err error

	if err = h.connect(); err != nil {
		return false
	}

	defer h.close()

	// TODO: Validate input
	dn := fmt.Sprintf("uid=%s,%s", username, h.getUsersDN())
	if err := h.ldap.Bind(dn, password); err == nil {
		return true
	}

	return false
}

func (h *LDAPHandler) disableUser(username string) error {
	return errors.New("Not implemented yet")
}

func (h *LDAPHandler) isAvailable(fn, sn, username string) error {
	// Check username
	if _, err := h.getUser(username); err == nil {
		return errors.New("Username not available")
	}

	// Check group
	if avail := h.isGroupAvailable(username); !avail {
		return errors.New("Group name not available")
	}

	return nil
}

func (h *LDAPHandler) isGroupAvailable(groupname string) bool {
	if err := h.connect(); err != nil {
		return false
	}

	defer h.close()

	// TODO: Validate input

	ldapRes, err := h.ldap.SearchAll(
		h.getGroupsDN(),
		openldap.LDAP_SCOPE_SUBTREE,
		fmt.Sprintf("(&(objectClass=posixGroup)(cn=%s))", groupname),
		[]string{})
	if err != nil {
		return false
	}

	return ldapRes.Count() == 0
}

func (h *LDAPHandler) getNextUID() (uint64, error) {
	if err := h.connect(); err != nil {
		return 0, err
	}

	defer h.close()

	if err := h.ldap.Bind(h.adminDN, h.adminPwd); err != nil {
		return 0, err
	}

	// Try to fetch uidNext, and increment it. If fail, retry a bit later
	for i := 0; i < 10; i++ {
		nextUID, errFetch := h._fetchNextUID(h.ldap)
		if errFetch != nil {
			log.Printf("Error fetching uidNext: %s\n", errFetch)
		} else {
			errInc := h._incrementNextUID(h.ldap, nextUID)
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

func (h *LDAPHandler) _fetchNextUID(ldap *openldap.Ldap) (uint64, error) {
	ldapRes, err := ldap.SearchAll(
		h.baseDN,
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

func (h *LDAPHandler) _incrementNextUID(ldap *openldap.Ldap, currentUID uint64) error {
	_currentUID := strconv.FormatUint(currentUID, 10)
	_nextUID := strconv.FormatUint(currentUID+1, 10)

	attrs := map[string][]string{
		"uidNumber": []string{_currentUID},
	}

	if err := ldap.ModifyDel(h.getUIDNextDN(), attrs); err != nil {
		return err
	}

	attrsAdd := map[string][]string{
		"uidNumber": []string{_nextUID},
	}

	if err := ldap.ModifyAdd(h.getUIDNextDN(), attrsAdd); err != nil {
		return err
	}

	return nil
}

//
//  Passwords
//
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
