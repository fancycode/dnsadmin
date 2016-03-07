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
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var help = flag.Bool("help", false, "show this help text")
	var root = flag.String("data", "", "root folder to store data")
	var www = flag.String("www", "", "folder containing website files to publish")
	var address = flag.String("address", "127.0.0.1:8080", "address to listen on")
	var logfile = flag.String("logfile", "", "logfile to write to (omit for stdout)")
	flag.Parse()

	if *help || *root == "" {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *logfile != "" {
		fp, err := os.OpenFile(*logfile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			fmt.Printf("Could not open logfile %s: %s", *logfile, err.Error())
			os.Exit(1)
		}
		defer fp.Close()
		log.SetOutput(fp)
	}
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	log.Printf("Using %s as data root", *root)
	if *www != "" {
		log.Printf("Using %s as www root", *www)
	}
	server, err := NewDnsAdminServer(*root, *www)
	if err != nil {
		log.Fatal("could not create server", err)
		return
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for {
			<-c
			log.Println("Received SIGHUP, reloading configuration")
			server.Reload()
		}
	}()

	if err := server.Run(*address); err != nil {
		log.Fatal(err)
		return
	}
}
