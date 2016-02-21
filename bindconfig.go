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
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

const (
	kMainConfFile   = "/etc/bind/named.conf.dnsadmin"
	kBindConfFolder = "/etc/bind/dnsadmin"
)

// Mapping username -> configuration file
func UpdateBindConfiguration(configs map[string][]byte) {
	has_changes := false
	var changed bool
	var err error
	var filenames []string
	for username, cfg := range configs {
		filename := filepath.Join(kBindConfFolder, username+".conf")
		if changed, err = UpdateFile(filename, cfg); err != nil {
			log.Printf("Could not save bind config at %s: %s", filename, err)
			continue
		}
		if err := os.Chmod(filename, 0644); err != nil {
			log.Printf("Could not change permissions of %s: %s", filename, err)
		}

		filenames = append(filenames, filename)
		if changed {
			has_changes = true
		}
	}

	var includes bytes.Buffer
	includes.WriteString("// This file has been generated automatically.\n")
	includes.WriteString("// DO NOT EDIT!\n\n")
	sort.Strings(filenames)
	for _, filename := range filenames {
		includes.WriteString("include \"" + filename + "\";\n")
	}
	if changed, err = UpdateFile(kMainConfFile, includes.Bytes()); err != nil {
		log.Printf("Could not save bind includes at %s: %s", kMainConfFile, err)
		return
	}
	if changed {
		has_changes = true
	}
	if err := os.Chmod(kMainConfFile, 0644); err != nil {
		log.Printf("Could not change permissions of %s: %s", kMainConfFile, err)
	}

	if !has_changes {
		log.Println("No files changed, not reloading bind9")
		return
	}

	cmd := exec.Command("/usr/sbin/service", "bind9", "reload")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Could not reload bind9 service: %s (%s)", err, string(output))
	} else {
		log.Println("bind9 was reloaded")
	}
}
