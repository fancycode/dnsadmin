/*
 * Copyright (C) 2016 Joachim Bauch <mail@joachim-bauch.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package main

import (
	"container/list"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
)

const (
	kMaxBodySize = 1024 * 1024
	kCookieName  = "DNSADMINAUTH"
	kUsernameKey = "username"

	kMinPasswordLength = 6

	// Start delaying if more than 3 failures in 5 minutes.
	kMaxFailures        = 3
	kMaxFailureDuration = 5 * time.Minute
	// Block further logins after 10 failures.
	kMaxFailuresEntries = 10
	// Never sleep longer than 5 seconds.
	kMaxFailureDelay = 5 * time.Second
)

type DelayEntry struct {
	failures list.List
}

type Delayer struct {
	lock         sync.Mutex
	entries      map[string]*DelayEntry
	activeDelays map[string]bool
}

func (d *Delayer) cleanupExpired() {
	d.lock.Lock()
	defer d.lock.Unlock()
	now := time.Now().UTC()
	for key, e := range d.entries {
		front := e.failures.Front()
		if now.Sub(front.Value.(time.Time)) < kMaxFailureDuration {
			continue
		}

		e.failures.Remove(front)
		if e.failures.Len() == 0 {
			delete(d.entries, key)
		}
	}
}

func (d *Delayer) getFailedDelay(key string) time.Duration {
	d.lock.Lock()
	defer d.lock.Unlock()
	e, found := d.entries[key]
	if !found {
		if d.entries == nil {
			d.entries = make(map[string]*DelayEntry)
			go func() {
				for {
					time.Sleep(time.Second)
					d.cleanupExpired()
				}
			}()
		}
		if d.activeDelays == nil {
			d.activeDelays = make(map[string]bool)
		}
		e = &DelayEntry{}
		d.entries[key] = e
	}

	now := time.Now().UTC()
	e.failures.PushBack(now)
	if e.failures.Len() <= kMaxFailures {
		return 0
	}

	front := e.failures.Front()
	first := front.Value.(time.Time)
	delta := now.Sub(first)
	// Delay request longer if it was failing a lot
	delay := (kMaxFailureDuration - delta) / 60
	if delay > kMaxFailureDelay {
		delay = kMaxFailureDelay
	}
	return delay
}

func (d *Delayer) IsDenied(key string) bool {
	d.lock.Lock()
	defer d.lock.Unlock()
	e, found := d.entries[key]
	if !found {
		return false
	}

	return e.failures.Len() >= kMaxFailuresEntries
}

func (d *Delayer) DelayFailed(key string) {
	delay := d.getFailedDelay(key)
	if delay <= 0 {
		return
	}

	d.lock.Lock()
	defer d.lock.Unlock()
	d.activeDelays[key] = true
	d.lock.Unlock()
	time.Sleep(delay)
	d.lock.Lock()
	d.activeDelays[key] = false
}

func (d *Delayer) IsDelayed(key string) bool {
	d.lock.Lock()
	defer d.lock.Unlock()
	return d.activeDelays[key]
}

func createCookie(r *http.Request, value string) *http.Cookie {
	return &http.Cookie{
		Name:  kCookieName,
		Value: value,
		Path:  "/",
	}
}

type dnsAdminServer struct {
	r       *mux.Router
	user    *userHandler
	delayer Delayer
}

func (s *dnsAdminServer) setHeaders(w http.ResponseWriter) {
	if h := w.Header(); h != nil {
		h.Set("Server", "dnsadmin")
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", "priviate, max-age=0, no-cache")
		h.Set("Pragma", "no-cache")
		h.Set("Expires", "-1")
	}
}

func (s *dnsAdminServer) returnSuccess(w http.ResponseWriter, code int, content interface{}) {
	s.setHeaders(w)
	w.WriteHeader(code)
	e := json.NewEncoder(w)
	e.Encode(map[string]interface{}{
		"status": "ok",
		"result": content,
	})
}

func (s *dnsAdminServer) returnError(w http.ResponseWriter, code int, content interface{}) {
	s.setHeaders(w)
	w.WriteHeader(code)
	e := json.NewEncoder(w)
	e.Encode(map[string]interface{}{
		"status": "error",
		"error":  content,
	})
}

// Private netmasks from RFC 1918 / RFC 4193
var privateMasks = func() []net.IPNet {
	masks := []net.IPNet{}
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		_, net, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		masks = append(masks, *net)
	}
	return masks
}()

// IsPublicIP returns true if the given IP can be routed on the Internet
func IsPublicIP(ip net.IP) bool {
	for _, mask := range privateMasks {
		if mask.Contains(ip) {
			return false
		}
	}
	return true
}

func (s *dnsAdminServer) getRemoteAddress(r *http.Request) string {
	if forwarded_for := r.Header.Get("X-Forwarded-For"); forwarded_for != "" {
		for _, part := range strings.Split(forwarded_for, ",") {
			// Use first non-local address
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if ip := net.ParseIP(part); ip == nil || ip.IsGlobalUnicast() || !IsPublicIP(ip) {
				continue
			}
			return part
		}
	}

	if real_ip := strings.TrimSpace(r.Header.Get("X-Real-Ip")); real_ip != "" {
		return real_ip
	}

	remoteAddr := r.RemoteAddr
	if pos := strings.LastIndex(remoteAddr, ":"); pos != -1 {
		remoteAddr = remoteAddr[:pos]
	}

	return remoteAddr
}

func (s *dnsAdminServer) decodeBody(w http.ResponseWriter, r *http.Request, body interface{}) bool {
	if r.ContentLength < 0 {
		s.returnError(w, http.StatusLengthRequired, "length_required")
		return false
	} else if r.ContentLength > kMaxBodySize {
		s.returnError(w, http.StatusRequestEntityTooLarge, "body_too_large")
		return false
	}

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&body); err != nil {
		if err == io.EOF {
			s.returnError(w, http.StatusBadRequest, "eof_while_decoding")
		} else {
			log.Printf("Decoding failed (%s)", err)
			s.returnError(w, http.StatusBadRequest, "decoding_failed")
		}
		return false
	}

	return true
}

func (s *dnsAdminServer) StatusHandler(w http.ResponseWriter, r *http.Request) {
	if user, _ := s.user.Authenticate(r); user != nil {
		w.Header().Set("X-dnsadmin-username", user.GetUsername())
	}
	s.returnSuccess(w, http.StatusOK, "ok")
}

func (s *dnsAdminServer) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if !s.decodeBody(w, r, &body) {
		return
	}

	username := body["username"]
	password := body["password"]
	if username == "" || password == "" {
		s.returnError(w, http.StatusBadRequest, "username_password_required")
		return
	}

	remote := s.getRemoteAddress(r)
	if s.delayer.IsDelayed(remote) {
		log.Printf("Login currently delayed from %s", remote)
		s.returnError(w, http.StatusForbidden, "login_delayed")
		return
	}

	if s.delayer.IsDenied(remote) {
		log.Printf("Login temporarily disabled from %s", remote)
		s.returnError(w, http.StatusForbidden, "login_temporarily_disabled")
		return
	}

	user, err := s.user.Login(username, password)
	if err != nil || user == nil {
		s.delayer.DelayFailed(remote)
		log.Printf("Login failed from %s", remote)
		s.returnError(w, http.StatusForbidden, "login_failed")
		return
	}

	log.Printf("User %s logged in from %s", user.GetUsername(), remote)
	s.user.SetCookie(w, r, user)
	s.returnSuccess(w, http.StatusOK, "login_success")
}

func (s *dnsAdminServer) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie := createCookie(r, "")
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
	s.returnSuccess(w, http.StatusOK, "logout_success")
}

func (s *dnsAdminServer) authenticateHandler(handler func(*user, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := s.user.Authenticate(r)
		if err != nil {
			if err == http.ErrNoCookie {
				s.returnError(w, http.StatusForbidden, "not_logged_in")
			} else {
				s.returnError(w, http.StatusForbidden, "login_expired")
			}
			return
		} else if user == nil {
			s.returnError(w, http.StatusNotFound, "unknown_user")
			return
		}

		w.Header().Set("X-DNS-Admin-Username", user.GetUsername())
		handler(user, w, r)
	}
}

func (s *dnsAdminServer) ChangePasswordHandler(user *user, w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if !s.decodeBody(w, r, &body) {
		return
	}

	password := body["password"]
	if password != strings.TrimSpace(password) {
		s.returnError(w, http.StatusNotAcceptable, "password_format_invalid")
		return
	} else if len(password) < kMinPasswordLength {
		s.returnError(w, http.StatusNotAcceptable, "password_too_short")
		return
	}

	if err := s.user.ChangePassword(user, password); err != nil {
		s.returnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Printf("User %s changed his password from %s", user.GetUsername(), s.getRemoteAddress(r))
	s.user.SetCookie(w, r, user)
	s.returnSuccess(w, http.StatusOK, "change_success")
}

func (s *dnsAdminServer) ListDomainsHandler(user *user, w http.ResponseWriter, r *http.Request) {
	domains := user.GetDomains()
	if domains == nil {
		domains = make(DomainList, 0)
	}
	s.returnSuccess(w, http.StatusOK, domains)
}

func (s *dnsAdminServer) AddSlaveHandler(user *user, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := vars["domain"]
	if domain == "" {
		s.returnError(w, http.StatusNotFound, "empty_domain")
		return
	}

	var body *Domain
	// NOTE: we only use "Master" from the sent data
	if !s.decodeBody(w, r, &body) {
		return
	}

	var added bool
	var err error
	if added, err = user.AddDomain(domain, kDomainTypeSlave, body.Master, false); err != nil {
		s.returnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if added {
		log.Printf("User %s added slave domain %s from %s", user.GetUsername(), domain, s.getRemoteAddress(r))
		s.user.TriggerUpdateBindConfiguration()
	}
	s.returnSuccess(w, http.StatusOK, domain)
}

func (s *dnsAdminServer) DeleteSlaveHandler(user *user, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := vars["domain"]
	if domain == "" {
		s.returnError(w, http.StatusNotFound, "empty_domain")
		return
	}

	var deleted bool
	var err error
	if deleted, err = user.DeleteDomain(domain); err != nil {
		s.returnError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if deleted {
		log.Printf("User %s removed slave domain %s from %s", user.GetUsername(), domain, s.getRemoteAddress(r))
		s.user.TriggerUpdateBindConfiguration()
	}
	s.returnSuccess(w, http.StatusOK, domain)
}

func (s *dnsAdminServer) LoadUsers() error {
	return s.user.Load()
}

func (s *dnsAdminServer) Reload() error {
	if err := s.LoadUsers(); err != nil {
		log.Println("could not load users", err)
	}
	return nil
}

func (s *dnsAdminServer) Run(addr string) error {
	log.Printf("Starting server on %s", addr)
	return http.ListenAndServe(addr, s.r)
}

func NewDnsAdminServer(root string) (*dnsAdminServer, error) {
	hashKey := securecookie.GenerateRandomKey(64)
	if hashKey == nil {
		return nil, errors.New("could not generate hash key")
	}
	blockKey := securecookie.GenerateRandomKey(32)
	if blockKey == nil {
		return nil, errors.New("could not generate block key")
	}

	server := &dnsAdminServer{
		r:    mux.NewRouter(),
		user: NewUserStorage(root, hashKey, blockKey),
	}
	if err := server.LoadUsers(); err != nil {
		return nil, err
	}

	s := server.r.PathPrefix("/api/v1").Subrouter()
	s.HandleFunc("/status", server.StatusHandler)
	s.HandleFunc("/user/login", server.LoginHandler).Methods("POST")
	s.HandleFunc("/user/logout", server.LogoutHandler).Methods("GET")
	s.HandleFunc("/user/change-password", server.authenticateHandler(server.ChangePasswordHandler)).Methods("POST")
	s.HandleFunc("/domain/list", server.authenticateHandler(server.ListDomainsHandler)).Methods("GET")
	s.HandleFunc("/slave/{domain}", server.authenticateHandler(server.AddSlaveHandler)).Methods("PUT")
	s.HandleFunc("/slave/{domain}", server.authenticateHandler(server.DeleteSlaveHandler)).Methods("DELETE")

	return server, nil
}
