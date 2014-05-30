// Copyright 2014 Kevin Gillette. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package lwa facilitates running local web applications.
//
// Chrome is currently the only browser supported; on each app invocation,
// a temporary browser profile will be created, and Chrome will be launched
// in incognito, "app" mode.
package lwa

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
)

const (
	tokensize  = 16 // raw size; tokensize * 2 is the hexcoded size
	cookiename = "lwa"
)

// when we add support for additional browsers, export this
type browser interface {
	Run(dir, url string) error
}

// Serve starts a browser instance and http server connected pair via a random
// port. If handler is nil, http.DefaultServerMux will be used. Serve is
// analogous to http.ListenAndServe, except that it will return with a nil
// error after the app browser window is closed.
//
// Serve implicitly authenticates the running OS user using random pre-shared
// tokens; these are loaded into the browser through a file readable only to
// the running OS user. Since content is served through localhost, non-root
// users are unable to observe traffic; further, keep-alives are disabled.
// After the browser is closed, Serve will block until all open, non-hijacked
// connections are closed before returning.
func Serve(handler http.Handler) error {
	browser, err := getBrowser()
	if err != nil {
		return err
	}
	auth, err := newAuthHandler(handler)
	if err != nil {
		return err
	}
	var nconn int32
	quit := make(chan struct{})
	done := make(chan struct{})
	server := http.Server{
		Handler: auth,
		ConnState: func(c net.Conn, s http.ConnState) {
			switch s {
			default:
				return
			case http.StateNew:
				atomic.AddInt32(&nconn, 1)
				return
			case http.StateClosed, http.StateHijacked:
				// if it's hijacked, the caller is application must further block if needed
			}
			if 0 < atomic.AddInt32(&nconn, -1) {
				return
			}
			// at this point there are no active connections,
			// so it's safe to teardown if we've been asked to
			select {
			case <-quit:
				close(done)
			default:
			}
		},
	}
	// no real benefits to keep-alive over the loopback
	// if you enable leave keep-alives enabled, the above ConnState callback might break
	server.SetKeepAlivesEnabled(false)

	// listen on a random loopback port
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return err
	}

	// block until connections are closed. by the time this runs, the listener is closed
	// and nconn cannot increase; if the server hasn't started yet, nconn will be 0 anyway
	defer func() {
		if 0 < atomic.LoadInt32(&nconn) {
			<-done
		}
	}()

	defer l.Close()

	prog := filepath.Base(os.Args[0])
	dir, err := ioutil.TempDir("", prog+".lwa.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	err = os.Chmod(dir, 0700)
	if err != nil {
		return err
	}
	u := url.URL{
		Scheme: "http",
		Host:   l.Addr().String(),
		Path:   string(auth.utoken),
	}
	brokerPath := filepath.Join(dir, "broker.html")
	err = writeBroker(brokerPath, u.String())
	if err != nil {
		return err
	}
	brokerPath, err = prepLocalPath(brokerPath)
	if err != nil {
		return err
	}

	go server.Serve(l)
	err = browser.Run(dir, brokerPath)
	if err != nil {
		return err
	}
	close(quit)
	return err
}

func genToken(size int) ([]byte, error) {
	token := make([]byte, 2*size)
	_, err := io.ReadFull(rand.Reader, token[size:])
	if err != nil {
		return nil, err
	}
	hex.Encode(token, token[size:])
	return token, nil
}

func newAuthHandler(handler http.Handler) (*authHandler, error) {
	const k = 2 * tokensize
	t, err := genToken(k)
	if err != nil {
		return nil, fmt.Errorf("token generation error: %v", err)
	}
	if handler == nil {
		handler = http.DefaultServeMux
	}
	ah := &authHandler{
		ctoken:  t[:k],
		utoken:  t[k:],
		handler: handler,
	}
	return ah, nil
}

type authHandler struct {
	sync.Mutex
	ctoken, utoken []byte
	handler        http.Handler
	connected      bool
}

func (ah *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if ah.checkAuth(r) {
		ah.handler.ServeHTTP(w, r)
	} else if ah.checkInitial(r) {
		c := &http.Cookie{
			Name:  cookiename,
			Value: string(ah.ctoken),
		}
		http.SetCookie(w, c)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
}

func (ah *authHandler) checkToken(x []byte, s string) bool {
	p, q := len(x), len(s)
	// len of new buffer should be at least len(x)
	l := subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(q, p), p, q)
	y := make([]byte, l)
	// y and s are all derived from the client; don't need constant time copy
	copy(y, s)
	return 1 == subtle.ConstantTimeCompare(x, y[:p])
}

func (ah *authHandler) checkAuth(r *http.Request) bool {
	c, err := r.Cookie(cookiename)
	if err != nil {
		return false
	}
	return ah.checkToken(ah.ctoken, c.Value)
}

func (ah *authHandler) checkInitial(r *http.Request) bool {
	ah.Lock()
	defer ah.Unlock()
	if !ah.connected && ah.checkToken(ah.utoken, r.URL.Path[1:]) {
		ah.connected = true
		return true
	}
	return false
}

func prepLocalPath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if path[0] != '/' {
		// specific to Windows file:/// urls
		path = "/" + path
	}
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	return u.String(), nil
}

func writeBroker(path, url string) error {
	const (
		head = `<!DOCTYPE html><title>connecting</title><meta http-equiv="refresh" content="0; url=`
		tail = `">`
	)
	l := len(head) + len(url) + len(tail)
	buf := make([]byte, 0, l)
	buf = append(buf, head...)
	buf = append(buf, url...)
	buf = append(buf, tail...)
	return ioutil.WriteFile(path, buf, 0600)
}

func getBrowser() (browser, error) {
	return new(chromeBrowser), nil
}

type chromeBrowser struct{}

func (b *chromeBrowser) Run(dir, url string) error {
	cmd := exec.Command("chrome", "--incognito", "--no-first-run", "--user-data-dir="+dir, "--app="+url)
	return cmd.Run()
}
