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
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"github.com/gardener/external-dns-management/pkg/dns"
	godns "github.com/miekg/dns"
	"k8s.io/client-go/util/flowcontrol"
	"net"
	"strings"
	"time"

	"github.com/gardener/external-dns-management/pkg/dns/provider"
	"github.com/gardener/external-dns-management/pkg/dns/provider/raw"
)

type Access interface {
	ListZones(consume func(zone *godns.SOA) (bool, error)) error
	ListRecords(zoneId string, consume func(record *godns.Envelope) (bool, error)) error

	raw.Executor
}

type access struct {
	rfc2136Config Rfc2136Config
	metrics       provider.Metrics
	rateLimiter   flowcontrol.RateLimiter
}

func NewAccess(rfc2136Config Rfc2136Config, metrics provider.Metrics, rateLimiter flowcontrol.RateLimiter) (Access, error) {
	return &access{rfc2136Config: rfc2136Config, metrics: metrics, rateLimiter: rateLimiter}, nil
}

func (this *access) ListZones(consume func(zone *godns.SOA) (bool, error)) error {
	this.metrics.AddGenericRequests(provider.M_LISTZONES, 1)
	this.rateLimiter.Accept()
	for _, zone := range this.rfc2136Config.zones {
		c := new(godns.Client)
		c.TsigSecret = map[string]string{this.rfc2136Config.tsigKeyName: this.rfc2136Config.tsigSecret}
		m := new(godns.Msg)
		m.SetQuestion(zone, godns.TypeSOA)
		m.RecursionDesired = false

		m.SetTsig(this.rfc2136Config.tsigKeyName, this.rfc2136Config.tsigAlgorithm, 300, time.Now().Unix())
		r, _, err := c.Exchange(m, this.rfc2136Config.nameserver)
		if err != nil {
			return err
		}
		if r.Rcode != godns.RcodeSuccess {
			continue
		}

		targetNs := strings.Split(this.rfc2136Config.nameserver, ":")
		for _, a := range r.Answer {
			if ns, ok := a.(*godns.SOA); ok {
				if ns.Ns == targetNs[0] {
					if cont, err := consume(ns); !cont || err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

func (this *access) ListRecords(zoneId string, consume func(record *godns.Envelope) (bool, error)) error {
	this.metrics.AddZoneRequests(zoneId, provider.M_LISTRECORDS, 1)
	this.rateLimiter.Accept()
	tr := new(godns.Transfer)
	tr.TsigSecret = map[string]string{this.rfc2136Config.tsigKeyName: this.rfc2136Config.tsigSecret}
	m := new(godns.Msg)
	m.SetAxfr(zoneId)
	m.SetTsig(this.rfc2136Config.tsigKeyName, this.rfc2136Config.tsigAlgorithm, 300, time.Now().Unix())

	c, err := tr.In(m, this.rfc2136Config.nameserver)
	if err != nil {
		return err
	}

	for envelope := range c {
		if envelope.Error != nil {
			return envelope.Error
		}
		if cont, err := consume(envelope); !cont || err != nil {
			return err
		}
	}
	return nil
}

func (this *access) CreateRecord(r raw.Record, zone provider.DNSHostedZone) error {
	m := new(godns.Msg)
	m.SetUpdate(zone.Domain())
	switch r.GetType() {
	case dns.RS_A:
		rr := new(godns.A)
		rr.Hdr = godns.RR_Header{Name: r.GetDNSName(), Rrtype: godns.TypeA, Class: godns.ClassINET, Ttl: uint32(r.GetTTL())}
		rr.A = net.ParseIP(r.GetValue())
		rrs := []godns.RR{rr}
		m.Insert(rrs)
	case dns.RS_CNAME:
		rr := new(godns.CNAME)
		rr.Hdr = godns.RR_Header{Name: r.GetDNSName(), Rrtype: godns.TypeCNAME, Class: godns.ClassINET, Ttl: uint32(r.GetTTL())}
		rr.Target = r.GetValue()
	case dns.RS_TXT:
		rr := new(godns.TXT)
		rr.Hdr = godns.RR_Header{Name: r.GetDNSName(), Rrtype: godns.TypeTXT, Class: godns.ClassINET, Ttl: uint32(r.GetTTL())}
		rr.Txt = []string{r.GetValue()}
	case dns.RS_NS:
		rr := new(godns.NS)
		rr.Hdr = godns.RR_Header{Name: r.GetDNSName(), Rrtype: godns.TypeNS, Class: godns.ClassINET, Ttl: uint32(r.GetTTL())}
		rr.Ns = r.GetValue()
	default:
		return fmt.Errorf("Cannot create unrecognized record type", r.GetType())
	}
	c := new(godns.Client)
	c.SingleInflight = true
	c.TsigSecret = map[string]string{this.rfc2136Config.tsigKeyName: this.rfc2136Config.tsigSecret}
	reply, _, err := c.Exchange(m, this.rfc2136Config.nameserver)
	if err != nil {
		return err
	}
	if reply != nil && reply.Rcode != godns.RcodeSuccess {
		return fmt.Errorf("Failure creating DNS record: ", reply.Rcode)
	}
	return nil
}

func (this *access) UpdateRecord(r raw.Record, zone provider.DNSHostedZone) error {
	a := r.(*Record)
	ttl := r.GetTTL()
	testTTL(&ttl)
	dnsRecord := cloudflare.DNSRecord{
		Type:    r.GetType(),
		Name:    r.GetDNSName(),
		Content: r.GetValue(),
		TTL:     ttl,
		ZoneID:  a.ZoneID,
	}
	this.metrics.AddZoneRequests(zone.Id(), provider.M_UPDATERECORDS, 1)
	this.rateLimiter.Accept()
	err := this.UpdateDNSRecord(a.ZoneID, r.GetId(), dnsRecord)
	return err
}

func (this *access) DeleteRecord(r raw.Record, zone provider.DNSHostedZone) error {
	a := r.(*Record)
	this.metrics.AddZoneRequests(zone.Id(), provider.M_DELETERECORDS, 1)
	this.rateLimiter.Accept()
	err := this.DeleteDNSRecord(a.ZoneID, r.GetId())
	return err
}

func (this *access) NewRecord(fqdn, rtype, value string, zone provider.DNSHostedZone, ttl int64) raw.Record {
	//return (*Record)(&godns.{
	//	Type:    rtype,
	//	Name:    fqdn,
	//	Content: value,
	//	TTL:     int(ttl),
	//	ZoneID:  zone.Id(),
	//})
	return &Record{&godns.RR_Header{Name: fqdn, Rrtype: rtype, Class: godns.ClassINET, Ttl: uint32(ttl)}, "", ""}
}

func testTTL(ttl *int) {
	if *ttl < 120 {
		*ttl = 1
	}
}
