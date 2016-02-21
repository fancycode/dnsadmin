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
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

const (
	kPasswordHashCost = bcrypt.DefaultCost
)

type storageData struct {
	Version int64           `json:"version"`
	Data    json.RawMessage `json:"data"`
}

type user struct {
	username string
	// bcrypt hash
	password []byte

	filename string

	lock    sync.Mutex
	domains map[string]*Domain
}

func (u *user) GetUsername() string {
	return u.username
}

func (u *user) GetDomains() DomainList {
	var result DomainList
	u.lock.Lock()
	defer u.lock.Unlock()
	for _, domain := range u.domains {
		result = append(result, domain)
	}
	return result
}

func (u *user) Load(root string) error {
	u.filename = filepath.Join(root, "domains_"+u.username+".conf")

	u.lock.Lock()
	defer u.lock.Unlock()
	data, err := ioutil.ReadFile(u.filename)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		u.domains = nil
		return nil
	}

	var storage storageData
	if err := json.Unmarshal(data, &storage); err != nil {
		return err
	}

	if storage.Version != 1 {
		return errors.New("unsupported storage version")
	}

	var domains DomainList
	if err := json.Unmarshal(storage.Data, &domains); err != nil {
		return err
	}

	u.domains = make(map[string]*Domain)
	for _, domain := range domains {
		u.domains[domain.Domain] = domain
	}
	return nil
}

func (u *user) storeDomains() error {
	if u.filename == "" {
		return errors.New("no filename set")
	}

	var domains DomainList
	for _, domain := range u.domains {
		domains = append(domains, domain)
	}

	data, err := json.Marshal(map[string]interface{}{
		"version": 1,
		"data":    domains,
	})
	if err != nil {
		return err
	}
	if _, err := UpdateFile(u.filename, data); err != nil {
		return err
	}
	return nil
}

func (u *user) AddDomain(domain string, domainType string, master net.IP, notify bool) (bool, error) {
	d := &Domain{
		Domain:     domain,
		DomainType: domainType,
		Master:     master,
		Notify:     notify,
	}

	u.lock.Lock()
	defer u.lock.Unlock()
	if u.domains == nil {
		u.domains = make(map[string]*Domain)
	}
	prev, found := u.domains[domain]
	if found && prev.Equal(d) {
		return false, nil
	}

	u.domains[domain] = d
	if err := u.storeDomains(); err != nil {
		if found {
			u.domains[domain] = prev
		}
		return false, err
	}
	return true, nil
}

func (u *user) DeleteDomain(domain string) (bool, error) {
	u.lock.Lock()
	defer u.lock.Unlock()
	prev, found := u.domains[domain]
	if !found {
		return false, nil
	}

	delete(u.domains, domain)
	if err := u.storeDomains(); err != nil {
		u.domains[domain] = prev
		return false, err
	}
	return true, nil
}

func (u *user) CheckPassword(password string) bool {
	return bcrypt.CompareHashAndPassword(u.password, []byte(password)) == nil
}
