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
	if testType == "MD5" {
		return md5.New
	} else if testType == "SHA-256" {
		return sha256.New
	}
	return nil
}
