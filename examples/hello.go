// Copyright 2014 Kevin Gillette. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"
	"log"
	"net/http"

	"github.com/extemporalgenome/lwa"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Hello from lwa!\nThe server will shut down when you close the browser\n")
}

func main() {
	err := lwa.Serve(http.HandlerFunc(Handler))
	if err != nil {
		log.Println(err)
	} else {
		log.Println("OK")
	}
}
