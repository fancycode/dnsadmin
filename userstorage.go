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
	"bufio"
	"bytes"
	"crypto/rand"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
)

const (
	// Only check every 10 seconds if the users file has changed
	kCheckUsersModifiedInterval = 10 * time.Second
	// Collapse 5 seconds of bind update requests.
	kUpdateBindCollapseTime = 5 * time.Second
)

var (
	dummyUser *user = &user{}
)

func init() {
	password := make([]byte, 8)
	if _, err := rand.Read(password); err != nil {
		panic(err)
	}
	hash, err := bcrypt.GenerateFromPassword(password, kPasswordHashCost)
	if err != nil {
		panic(err)
	}
	dummyUser.password = hash
}

type userHandler struct {
	c *securecookie.SecureCookie

	// mapping username -> user object
	lock      sync.RWMutex
	stat      os.FileInfo
	users     map[string]*user
	nextCheck time.Time

	root          string
	usersFilename string

	updateChan  chan bool
	updateTimer *time.Timer
}

func (u *userHandler) checkModified() {
	now := time.Now()
	if now.Before(u.nextCheck) {
		return
	}

	stat, err := os.Stat(u.usersFilename)
	if err != nil {
		log.Printf("Could not check %s: %s", u.usersFilename, err)
		return
	}

	u.lock.RLock()
	if stat.Size() == u.stat.Size() && stat.ModTime() == u.stat.ModTime() {
		u.lock.RUnlock()
		return
	}
	u.lock.RUnlock()

	log.Printf("File %s has changed, reloading", u.usersFilename)
	if err := u.Load(); err != nil {
		log.Printf("Could not load %s: %s", u.usersFilename, err)
	}
}

func (u *userHandler) doLoad() (map[string]*user, error) {
	fp, err := os.Open(u.usersFilename)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	users := make(map[string]*user)
	s := bufio.NewScanner(fp)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || line[0] == '#' {
			// Skip empty lines and comments
			continue
		}

		pos := strings.IndexRune(line, ':')
		if pos == -1 {
			log.Println("Line format is invalid:", line)
			continue
		}

		user := &user{
			username: line[:pos],
			password: []byte(line[pos+1:]),
		}
		if err := user.Load(u.root); err != nil {
			log.Printf("Could not load user %s: %s", user.username, err)
			continue
		}
		users[user.username] = user
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	log.Printf("Loaded %d users", len(users))
	return users, nil
}

func (u *userHandler) Load() error {
	stat, err := os.Stat(u.usersFilename)
	if err != nil {
		return err
	}

	u.lock.Lock()
	defer u.lock.Unlock()

	users, err := u.doLoad()
	if err != nil {
		return err
	}

	u.users = users
	u.stat = stat
	u.nextCheck = time.Now().Add(kCheckUsersModifiedInterval)
	u.TriggerUpdateBindConfiguration()
	return nil
}

func (u *userHandler) doStore() error {
	var w bytes.Buffer
	for _, e := range u.users {
		w.WriteString(e.username + ":" + string(e.password) + "\n")
	}

	if _, err := UpdateFile(u.usersFilename, w.Bytes()); err != nil {
		return err
	}

	stat, err := os.Stat(u.usersFilename)
	if err == nil {
		u.stat = stat
	}
	u.nextCheck = time.Now().Add(kCheckUsersModifiedInterval)
	u.TriggerUpdateBindConfiguration()
	return nil
}

func (u *userHandler) SetCookie(w http.ResponseWriter, user *user) {
	value := map[string]string{
		kUsernameKey: user.GetUsername(),
	}

	if encoded, err := u.c.Encode(kCookieName, value); err == nil {
		cookie := &http.Cookie{
			Name:  kCookieName,
			Value: encoded,
			Path:  "/",
		}

		http.SetCookie(w, cookie)
	}
}

func (u *userHandler) Authenticate(r *http.Request) (*user, error) {
	cookie, err := r.Cookie(kCookieName)
	if err != nil {
		return nil, err
	}

	value := make(map[string]string)
	if err := u.c.Decode(kCookieName, cookie.Value, &value); err != nil {
		return nil, err
	}

	u.checkModified()

	u.lock.RLock()
	defer u.lock.RUnlock()
	user, found := u.users[value[kUsernameKey]]
	if !found {
		return nil, nil
	}

	return user, nil
}

func (u *userHandler) Login(username string, password string) (*user, error) {
	u.checkModified()

	u.lock.RLock()
	defer u.lock.RUnlock()
	user, found := u.users[username]
	if !found {
		// Avoid returning too fast for unknown users to prevent "guessing" of
		// existing user names.
		dummyUser.CheckPassword(password)
		return nil, nil
	}

	if !user.CheckPassword(password) {
		return nil, nil
	}

	return user, nil
}

func (u *userHandler) ChangePassword(user *user, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), kPasswordHashCost)
	if err != nil {
		return err
	}

	u.lock.Lock()
	defer u.lock.Unlock()

	old_password := user.password
	user.password = hash
	if err := u.doStore(); err != nil {
		user.password = old_password
		return err
	}

	return nil
}

func (u *userHandler) TriggerUpdateBindConfiguration() {
	u.updateChan <- true
}

func (u *userHandler) updateBindConfiguration() {
	<-u.updateChan

	if u.updateTimer != nil {
		// Update already scheduled
		return
	}

	u.updateTimer = time.AfterFunc(kUpdateBindCollapseTime, func() {
		log.Println("Updating bind configuration")
		u.updateTimer = nil

		configs := make(map[string][]byte)
		u.lock.RLock()
		for username, user := range u.users {
			domains := user.GetDomains()
			sort.Sort(domains)
			cfg, err := domains.GenerateBindConfig()
			if err != nil {
				log.Printf("Could not generate bind config for %s: %s", username, err)
				continue
			}

			configs[username] = cfg
		}
		u.lock.RUnlock()

		UpdateBindConfiguration(configs)
	})
}

func NewUserStorage(root string, hashKey []byte, blockKey []byte) *userHandler {
	result := &userHandler{
		c:             securecookie.New(hashKey, blockKey),
		users:         make(map[string]*user),
		root:          root,
		usersFilename: filepath.Join(root, "users.conf"),
		updateChan:    make(chan bool),
	}

	go func() {
		for {
			result.updateBindConfiguration()
		}
	}()
	return result
}
