// Copyright 2013 M-Lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The digest package provides an implementation of http.RoundTripper that takes
// care of HTTP Digest Authentication (http://www.ietf.org/rfc/rfc2617.txt).
// This only implements the MD5 and "auth" portions of the RFC, but that covers
// the majority of avalible server side implementations including apache web
// server.
//

package digest

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"testing"
)

var cnonce = "0a4f113b"

func TestH(t *testing.T) {
	t.Run("MD5", func(t *testing.T) {
		r1 := h("Mufasa:testrealm@host.com:Circle Of Life", md5.New)
		expected := "939e7578ed9e3c518a452acee763bce9"
		if r1 != expected {
			t.Errorf("expected=%s, but got=%s\n", expected, r1)
		}

		r2 := h("GET:/dir/index.html", md5.New)
		expected = "39aff3a2bab6126f332b942af96d3366"
		if r2 != expected {
			t.Errorf("expected=%s, but got=%s\n", expected, r2)
		}

		r3 := h(fmt.Sprintf("%s:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:%s", r1, r2), md5.New)
		expected = "6629fae49393a05397450978507c4ef1"
		if r3 != expected {
			t.Errorf("expected=%s, but got=%s\n", expected, r3)
		}
	})
	t.Run("SHA-256", func(t *testing.T) {
		r1 := h("Mufasa:testrealm@host.com:Circle Of Life", sha256.New)
		expected := "3ba6cd94661c5ef34598040c868f13b8775df29109986be50ad35ae537dd3aa4"
		if r1 != expected {
			t.Errorf("expected=%s, but got=%s\n", expected, r1)
		}

		r2 := h("GET:/dir/index.html", sha256.New)
		expected = "9a3fdae9a622fe8de177c24fa9c070f2b181ec85e15dcbdc32e10c82ad450b04"
		if r2 != expected {
			t.Errorf("expected=%s, but got=%s\n", expected, r2)
		}

		r3 := h(fmt.Sprintf("%s:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:%s", r1, r2), sha256.New)
		expected = "5abdd07184ba512a22c53f41470e5eea7dcaa3a93a59b630c13dfe0a5dc6e38b"
		if r3 != expected {
			t.Errorf("expected=%s, but got=%s\n", expected, r3)
		}
	})
}

func TestKd(t *testing.T) {
	t.Run("MD5", func(t *testing.T) {
		r1 := kd("939e7578ed9e3c518a452acee763bce9",
			"dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:39aff3a2bab6126f332b942af96d3366",
			md5.New)
		if r1 != "6629fae49393a05397450978507c4ef1" {
			t.Fail()
		}
	})

	t.Run("SHA-256", func(t *testing.T) {
		r1 := kd("939e7578ed9e3c518a452acee763bce9",
			"dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:39aff3a2bab6126f332b942af96d3366",
			sha256.New)
		if r1 != "ca165e8478c14bd2a5c64cc86ffe17c277ee2cff3e98c330ee5565e8e206ca3e" {
			t.Fail()
		}
	})
}

func TestHa1(t *testing.T) {
	t.Run("MD5", func(t *testing.T) {
		cred := &credentials{
			Username:   "Mufasa",
			Realm:      "testrealm@host.com",
			Nonce:      "dcd98b7102dd2f0e8b11d0f600bfb0c093",
			DigestURI:  "/dir/index.html",
			Algorithm:  "MD5",
			Opaque:     "5ccc069c403ebaf9f0171e9517f40e41",
			MessageQop: "auth",
			method:     "GET",
			password:   "Circle Of Life",
			impl:       md5.New,
		}
		r1 := cred.ha1()
		if r1 != "939e7578ed9e3c518a452acee763bce9" {
			t.Fail()
		}
	})
	t.Run("SHA-256", func(t *testing.T) {
		cred := &credentials{
			Username:   "Mufasa",
			Realm:      "testrealm@host.com",
			Nonce:      "dcd98b7102dd2f0e8b11d0f600bfb0c093",
			DigestURI:  "/dir/index.html",
			Algorithm:  "SHA-256",
			Opaque:     "5ccc069c403ebaf9f0171e9517f40e41",
			MessageQop: "auth",
			method:     "GET",
			password:   "Circle Of Life",
			impl:       sha256.New,
		}
		r1 := cred.ha1()
		if r1 != "3ba6cd94661c5ef34598040c868f13b8775df29109986be50ad35ae537dd3aa4" {
			t.Fail()
		}
	})
}

func TestHa2(t *testing.T) {
	t.Run("MD5", func(t *testing.T) {
		cred := &credentials{
			Username:   "Mufasa",
			Realm:      "testrealm@host.com",
			Nonce:      "dcd98b7102dd2f0e8b11d0f600bfb0c093",
			DigestURI:  "/dir/index.html",
			Algorithm:  "MD5",
			Opaque:     "5ccc069c403ebaf9f0171e9517f40e41",
			MessageQop: "auth",
			method:     "GET",
			password:   "Circle Of Life",
			impl:       md5.New,
		}
		r1 := cred.ha2()
		if r1 != "39aff3a2bab6126f332b942af96d3366" {
			t.Fail()
		}
	})
	t.Run("SHA-256", func(t *testing.T) {
		cred := &credentials{
			Username:   "Mufasa",
			Realm:      "testrealm@host.com",
			Nonce:      "dcd98b7102dd2f0e8b11d0f600bfb0c093",
			DigestURI:  "/dir/index.html",
			Algorithm:  "MD5",
			Opaque:     "5ccc069c403ebaf9f0171e9517f40e41",
			MessageQop: "auth",
			method:     "GET",
			password:   "Circle Of Life",
			impl:       sha256.New,
		}
		r1 := cred.ha2()
		if r1 != "9a3fdae9a622fe8de177c24fa9c070f2b181ec85e15dcbdc32e10c82ad450b04" {
			t.Fail()
		}
	})
}

func TestResp(t *testing.T) {
	t.Run("MD5", func(t *testing.T) {
		cred := &credentials{
			Username:   "Mufasa",
			Realm:      "testrealm@host.com",
			Nonce:      "dcd98b7102dd2f0e8b11d0f600bfb0c093",
			DigestURI:  "/dir/index.html",
			Algorithm:  "MD5",
			Opaque:     "5ccc069c403ebaf9f0171e9517f40e41",
			MessageQop: "auth",
			method:     "GET",
			password:   "Circle Of Life",
			impl:       md5.New,
		}
		r1, err := cred.resp(cnonce)
		if err != nil {
			t.Fail()
		}
		if r1 != "6629fae49393a05397450978507c4ef1" {
			t.Fail()
		}
	})
	t.Run("MD5", func(t *testing.T) {
		cred := &credentials{
			Username:   "Mufasa",
			Realm:      "testrealm@host.com",
			Nonce:      "dcd98b7102dd2f0e8b11d0f600bfb0c093",
			DigestURI:  "/dir/index.html",
			Algorithm:  "SHA-256",
			Opaque:     "5ccc069c403ebaf9f0171e9517f40e41",
			MessageQop: "auth",
			method:     "GET",
			password:   "Circle Of Life",
			impl:       sha256.New,
		}
		r1, err := cred.resp(cnonce)
		if err != nil {
			t.Fail()
		}
		if r1 != "5abdd07184ba512a22c53f41470e5eea7dcaa3a93a59b630c13dfe0a5dc6e38b" {
			t.Fail()
		}
	})
}
