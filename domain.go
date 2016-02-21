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
	"bytes"
	"text/template"
	"unicode"
)

import (
	"net"
)

const (
	kDomainTypeSlave = "slave"
)

type Domain struct {
	Domain     string `json:"domain"`
	DomainType string `json:"type"`
	Master     net.IP `json:"master"`
	Notify     bool   `json:"notify,omitempty"`
}

func (d *Domain) Equal(other *Domain) bool {
	return d.Domain == other.Domain &&
		d.DomainType == other.DomainType &&
		d.Master.Equal(other.Master) &&
		d.Notify == other.Notify
}

type DomainList []*Domain

func (l DomainList) Len() int {
	return len(l)
}

func (l DomainList) Less(i, j int) bool {
	return l[i].Domain < l[j].Domain
}

func (l DomainList) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

var (
	slaveTemplate = template.Must(template.New("slave").Parse(`
zone "{{ .Domain }}" in {
	type slave;
	masters { {{ .Master }}; };
	file "/var/cache/bind/dnsadmin-slave-{{ .Domain }}.zone";
	allow-transfer { trusted-servers; };
};
`))
)

func (l DomainList) GenerateBindConfig() ([]byte, error) {
	var output bytes.Buffer
	for _, domain := range l {
		if domain.DomainType != kDomainTypeSlave {
			continue
		}
		err := slaveTemplate.Execute(&output, map[string]string{
			"Domain": domain.Domain,
			"Master": domain.Master.String(),
		})
		if err != nil {
			return nil, err
		}
	}
	return bytes.TrimLeftFunc(output.Bytes(), unicode.IsSpace), nil
}
