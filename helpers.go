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
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
)

// UpdateFile atomically updates the contents of the given file.
func UpdateFile(filename string, contents []byte) (bool, error) {
	// We follow symlinks
	if fn, err := os.Readlink(filename); err == nil || (fn != "" && os.IsNotExist(err)) {
		if filepath.IsAbs(fn) {
			filename = fn
		} else {
			filename = filepath.Join(filepath.Dir(filename), fn)
		}
	}

	if prev, err := ioutil.ReadFile(filename); err == nil && bytes.Equal(prev, contents) {
		// No change required
		return false, nil
	}

	fp, err := ioutil.TempFile(filepath.Dir(filename), "temp")
	if err != nil {
		return false, err
	}
	tempname := fp.Name()

	defer func() {
		fp.Close()
		if tempname != "" {
			os.Remove(tempname)
		}
	}()

	if _, err := fp.Write(contents); err != nil {
		return false, err
	}
	if err := fp.Close(); err != nil {
		return false, err
	}
	if stat, err := os.Stat(filename); err == nil {
		// NOTE: we ignore errors when copying permissions/ownership information.
		os.Chmod(tempname, stat.Mode())
		if os_stat, ok := stat.Sys().(*syscall.Stat_t); ok {
			os.Chown(tempname, int(os_stat.Uid), int(os_stat.Gid))
		}
	}
	if err := os.Rename(tempname, filename); err != nil {
		return false, err
	}
	// No need to cleanup temporary file (was moved)
	tempname = ""
	return true, nil
}
