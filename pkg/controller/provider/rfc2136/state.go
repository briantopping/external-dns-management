/*
 * Copyright 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *
 */

package rfc2136

import (
	godns "github.com/miekg/dns"
	"strings"
	"unsafe"

	"github.com/gardener/external-dns-management/pkg/dns/provider/raw"
)

type Record struct {
	godns.RR
	Name string
	Id   string
}

var _ raw.Record = &Record{}

func (r *Record) GetType() string    { return godns.TypeToString[r.Header().Rrtype] }
func (r *Record) GetId() string      { return r.Id } //r.Header() }
func (r *Record) GetDNSName() string { return r.Name }
func (r *Record) GetValue() string {
	if r.Header().Rrtype == godns.TypeTXT {
		t := *(*godns.TXT)(unsafe.Pointer(r))
		return raw.EnsureQuotedText(strings.Join(t.Txt, ","))
	}
	return r.String()
}
func (r *Record) GetTTL() int      { return int(r.Header().Ttl) }
func (r *Record) SetTTL(ttl int)   { r.Header().Ttl = uint32(ttl) }
func (r *Record) Copy() raw.Record { n := *r; return &n }
