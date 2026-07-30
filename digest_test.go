// Copyright 2013 M-Lab, 2020 MongoDB, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package digest

import (
	"crypto/md5" //nolint:gosec // valid for digest
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var cnonce = "0a4f113b"

func TestH(t *testing.T) {
	testCases := map[string]map[string]string{
		"MD5": {
			"r1":          "Mufasa:testrealm@host.com:Circle Of Life",
			"r2":          "GET:/dir/index.html",
			"expected_r1": "939e7578ed9e3c518a452acee763bce9",
			"expected_r2": "39aff3a2bab6126f332b942af96d3366",
			"expected_r3": "72e6fcaeee7554ad095e1147cd8f3f13",
		},
		"SHA-256": {
			"r1":          "Mufasa:testrealm@host.com:Circle Of Life",
			"r2":          "GET:/dir/index.html",
			"expected_r1": "3ba6cd94661c5ef34598040c868f13b8775df29109986be50ad35ae537dd3aa4",
			"expected_r2": "9a3fdae9a622fe8de177c24fa9c070f2b181ec85e15dcbdc32e10c82ad450b04",
			"expected_r3": "705e2bcd4503344546454cc767a5e3107dc09f86dc898d840fff18b257f0b62f",
		},
	}

	for testType, values := range testCases {
		r1 := values["r1"]
		expectedR1 := values["expected_r1"]
		r2 := values["r2"]
		expectedR2 := values["expected_r2"]
		expectedR3 := values["expected_r3"]
		tt := testType
		t.Run(tt, func(t *testing.T) {
			var err error
			hFunc := testHashingFunc(tt)
			r1Got, err := h(r1, hFunc)
			if err != nil {
				t.Fatal(err)
			}
			if r1Got != expectedR1 {
				t.Errorf("expectedR1=%s, but got=%s\n", expectedR1, r1Got)
			}
			r2Got, err := h(r2, hFunc)
			if err != nil {
				t.Fatal(err)
			}
			if r2Got != expectedR2 {
				t.Errorf("expectedR2=%s, but got=%s\n", expectedR2, r2Got)
			}
			r3, err := h(fmt.Sprintf("%s:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:%s", r1, r2), hFunc)
			if err != nil {
				t.Fatal(err)
			}
			if r3 != expectedR3 {
				t.Errorf("expectedR3=%s, but got=%s\n", expectedR3, r3)
			}
		})
	}
}

func TestKd(t *testing.T) {
	testCases := map[string]map[string]string{
		"MD5": {
			"secret":   "939e7578ed9e3c518a452acee763bce9",
			"data":     "dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:39aff3a2bab6126f332b942af96d3366",
			"expected": "6629fae49393a05397450978507c4ef1",
		},
		"SHA-256": {
			"secret":   "939e7578ed9e3c518a452acee763bce9",
			"data":     "dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:39aff3a2bab6126f332b942af96d3366",
			"expected": "ca165e8478c14bd2a5c64cc86ffe17c277ee2cff3e98c330ee5565e8e206ca3e",
		},
	}

	for testType, values := range testCases {
		secret := values["secret"]
		data := values["data"]
		expected := values["expected"]
		tt := testType
		t.Run(tt, func(t *testing.T) {
			hFunc := testHashingFunc(tt)
			if r1, err := kd(secret, data, hFunc); r1 != expected {
				if err != nil {
					t.Fatal(err)
				}
				t.Errorf("expected=%s, but got=%s\n", expected, r1)
			}
		})
	}
}

func TestHa1(t *testing.T) {
	testCases := map[string]map[string]string{
		"MD5": {
			"expected": "939e7578ed9e3c518a452acee763bce9",
		},
		"SHA-256": {
			"expected": "3ba6cd94661c5ef34598040c868f13b8775df29109986be50ad35ae537dd3aa4",
		},
	}

	for testType, values := range testCases {
		expected := values["expected"]
		tt := testType
		t.Run(tt, func(t *testing.T) {
			hFunc := testHashingFunc(tt)
			cred := &credentials{
				Username:   "Mufasa",
				Realm:      "testrealm@host.com",
				Nonce:      "dcd98b7102dd2f0e8b11d0f600bfb0c093",
				DigestURI:  "/dir/index.html",
				Algorithm:  tt,
				Opaque:     "5ccc069c403ebaf9f0171e9517f40e41",
				MessageQop: "auth",
				method:     "GET",
				password:   "Circle Of Life",
				impl:       hFunc,
			}
			if r1, err := cred.ha1(); r1 != expected {
				if err != nil {
					t.Fatal(err)
				}
				t.Errorf("expected=%s, but got=%s\n", expected, r1)
			}
		})
	}
}

func TestHa2(t *testing.T) {
	testCases := map[string]map[string]string{
		"MD5": {
			"expected": "39aff3a2bab6126f332b942af96d3366",
		},
		"SHA-256": {
			"expected": "9a3fdae9a622fe8de177c24fa9c070f2b181ec85e15dcbdc32e10c82ad450b04",
		},
	}

	for testType, values := range testCases {
		expected := values["expected"]
		tt := testType
		t.Run(tt, func(t *testing.T) {
			hFunc := testHashingFunc(tt)
			cred := &credentials{
				Username:   "Mufasa",
				Realm:      "testrealm@host.com",
				Nonce:      "dcd98b7102dd2f0e8b11d0f600bfb0c093",
				DigestURI:  "/dir/index.html",
				Algorithm:  tt,
				Opaque:     "5ccc069c403ebaf9f0171e9517f40e41",
				MessageQop: "auth",
				method:     "GET",
				password:   "Circle Of Life",
				impl:       hFunc,
			}
			if r1, err := cred.ha2(); r1 != expected {
				if err != nil {
					t.Fatal(err)
				}
				t.Errorf("expected=%s, but got=%s\n", expected, r1)
			}
		})
	}
}

func TestResp(t *testing.T) {
	testCases := map[string]map[string]string{
		"MD5": {
			"expected": "6629fae49393a05397450978507c4ef1",
		},
		"SHA-256": {
			"expected": "5abdd07184ba512a22c53f41470e5eea7dcaa3a93a59b630c13dfe0a5dc6e38b",
		},
	}

	for testType, values := range testCases {
		expected := values["expected"]
		tt := testType
		t.Run(tt, func(t *testing.T) {
			hFunc := testHashingFunc(tt)
			cred := &credentials{
				Username:   "Mufasa",
				Realm:      "testrealm@host.com",
				Nonce:      "dcd98b7102dd2f0e8b11d0f600bfb0c093",
				DigestURI:  "/dir/index.html",
				Algorithm:  tt,
				Opaque:     "5ccc069c403ebaf9f0171e9517f40e41",
				MessageQop: "auth",
				method:     "GET",
				password:   "Circle Of Life",
				impl:       hFunc,
			}
			if r1, err := cred.resp(cnonce); err != nil || r1 != expected {
				t.Errorf("expected=%s, but got=%s\n", expected, r1)
			}
		})
	}
}

func testHashingFunc(testType string) hashingFunc {
	switch testType {
	case "MD5":
		return md5.New
	case "SHA-256":
		return sha256.New
	}
	return nil
}

// TestStaleNonceRetry verifies that RoundTrip retries when the server
// returns 401 with stale=true (RFC 7616 §3.2), and succeeds on a later
// challenge-response cycle.
func TestStaleNonceRetry(t *testing.T) {
	totalRequests := 0
	authRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalRequests++
		auth := r.Header.Get("Authorization")

		if auth == "" {
			// Unauthenticated request — return challenge.
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		authRequests++
		if authRequests == 1 {
			// First auth'd request — nonce is stale.
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth", stale=true`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Second auth'd request — success.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))
	defer server.Close()

	transport := &Transport{
		Username:  "user",
		Password:  "pass",
		Transport: http.DefaultTransport,
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// 4 total requests: 2 challenges (unauth'd) + 2 auth'd (first stale, second success).
	if totalRequests != 4 {
		t.Errorf("expected 4 total requests, got %d", totalRequests)
	}
}

// TestNonStale401NoRetry verifies that RoundTrip does NOT retry when the
// server returns 401 without stale=true (genuine credential failure).
func TestNonStale401NoRetry(t *testing.T) {
	totalRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalRequests++
		auth := r.Header.Get("Authorization")

		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Auth'd request — 401 without stale=true (genuine failure).
		w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	transport := &Transport{
		Username:  "user",
		Password:  "pass",
		Transport: http.DefaultTransport,
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	// 2 total requests: 1 challenge + 1 auth'd. No retry.
	if totalRequests != 2 {
		t.Errorf("expected 2 total requests, got %d", totalRequests)
	}
}

// TestStaleNonceRetryWithBody verifies that the request body is correctly
// replayed on a stale-nonce retry for a POST request.
func TestStaleNonceRetryWithBody(t *testing.T) {
	authRequests := 0
	var lastBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)

		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		authRequests++
		lastBody = string(body)

		if authRequests == 1 {
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth", stale=true`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &Transport{
		Username:  "user",
		Password:  "pass",
		Transport: http.DefaultTransport,
	}

	client := &http.Client{Transport: transport}

	// strings.NewReader gets a GetBody from http.NewRequest, exercising
	// the GetBody replay path.
	req, err := http.NewRequest("POST", server.URL, strings.NewReader("test body content"))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	if lastBody != "test body content" {
		t.Errorf("expected body to be replayed, got %q", lastBody)
	}
}

// TestStaleNonceRetryMultiple verifies that RoundTrip retries multiple times
// when the server keeps returning stale=true, and eventually succeeds.
func TestStaleNonceRetryMultiple(t *testing.T) {
	totalRequests := 0
	authRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalRequests++
		auth := r.Header.Get("Authorization")

		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		authRequests++
		if authRequests < 3 {
			// First two auth'd requests — stale.
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth", stale=true`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Third auth'd request — success.
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &Transport{
		Username:  "user",
		Password:  "pass",
		Transport: http.DefaultTransport,
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// 3 challenge cycles × 2 requests each (unauth'd + auth'd) = 6 total.
	if totalRequests != 6 {
		t.Errorf("expected 6 total requests, got %d", totalRequests)
	}
}

// TestStaleNonceRetryMaxBound verifies that RoundTrip stops retrying after
// DefaultMaxStaleRetries when the server always returns stale=true, and
// returns the final 401 to the caller.
func TestStaleNonceRetryMaxBound(t *testing.T) {
	totalRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalRequests++
		auth := r.Header.Get("Authorization")

		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Always stale — never succeeds.
		w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth", stale=true`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	transport := &Transport{
		Username:  "user",
		Password:  "pass",
		Transport: http.DefaultTransport,
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	// (DefaultMaxStaleRetries + 1) challenge cycles × 2 requests each = 8 total.
	expected := (DefaultMaxStaleRetries + 1) * 2
	if totalRequests != expected {
		t.Errorf("expected %d total requests, got %d", expected, totalRequests)
	}
}

// TestStaleNonceRetryCustomMax verifies that MaxStaleRetries on the Transport
// overrides the default.
func TestStaleNonceRetryCustomMax(t *testing.T) {
	totalRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalRequests++
		auth := r.Header.Get("Authorization")

		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth", stale=true`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	transport := &Transport{
		Username:        "user",
		Password:        "pass",
		Transport:       http.DefaultTransport,
		MaxStaleRetries: 1,
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	// (1 + 1) challenge cycles × 2 requests each = 4 total.
	if totalRequests != 4 {
		t.Errorf("expected 4 total requests, got %d", totalRequests)
	}
}

// TestStaleNonceRetryDisabled verifies that a negative MaxStaleRetries
// disables stale retry entirely — the 401 is returned without retry.
func TestStaleNonceRetryDisabled(t *testing.T) {
	totalRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalRequests++
		auth := r.Header.Get("Authorization")

		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="test-nonce", qop="auth", stale=true`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	transport := &Transport{
		Username:        "user",
		Password:        "pass",
		Transport:       http.DefaultTransport,
		MaxStaleRetries: -1,
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	// 1 challenge cycle × 2 requests = 2 total. No stale retry.
	if totalRequests != 2 {
		t.Errorf("expected 2 total requests, got %d", totalRequests)
	}
}
