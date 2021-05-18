/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. h file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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
	"encoding/json"
	"fmt"
	"github.com/gardener/external-dns-management/pkg/dns/provider/raw"
	"github.com/miekg/dns"
	"strings"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"k8s.io/client-go/util/flowcontrol"

	"github.com/gardener/external-dns-management/pkg/dns/provider"
)

type Handler struct {
	provider.DefaultDNSHandler
	config        provider.DNSHandlerConfig
	cache         provider.ZoneCache
	access        Access
	rfc2136Config Rfc2136Config
	rateLimiter   flowcontrol.RateLimiter
}

type Rfc2136Config struct {
	nameserver    string   `json:"nameserver"` // form of addr:port
	tsigAlgorithm string   `json:"tsigAlgorithm"`
	tsigKeyName   string   `json:"tsigKeyName"`
	tsigSecret    string   `json:"tsigSecret"`
	zones         []string `json:"zones"`
}

var supportedAlgorithms = map[string]string{
	"HMACMD5":    dns.HmacMD5,
	"HMACSHA1":   dns.HmacSHA1,
	"HMACSHA256": dns.HmacSHA256,
	"HMACSHA512": dns.HmacSHA512,
}

var _ provider.DNSHandler = &Handler{}

// TestRfc2136 allows tests to access rfc2136ed DNSHosted Zones
var TestRfc2136 *provider.InMemory

func NewHandler(config *provider.DNSHandlerConfig) (provider.DNSHandler, error) {
	rfc2136 := provider.NewInMemory()
	TestRfc2136 = rfc2136

	h := &Handler{
		DefaultDNSHandler: provider.NewDefaultDNSHandler(TYPE_CODE),
		config:            *config,
		rateLimiter:       config.RateLimiter,
	}

	err := json.Unmarshal(config.Config.Raw, &h.rfc2136Config)
	if err != nil {
		return nil, fmt.Errorf("unmarshal rfc2136 providerConfig failed with: %s", err)
	}

	algorithm := h.rfc2136Config.tsigAlgorithm
	if algorithm == "" {
		algorithm = dns.HmacMD5
	} else {
		if value, ok := supportedAlgorithms[strings.ToUpper(algorithm)]; ok {
			algorithm = value
		} else {
			return nil, fmt.Errorf("The algorithm '%v' is not supported", algorithm)

		}
	}
	h.rfc2136Config.tsigAlgorithm = algorithm

	access, err := NewAccess(h.rfc2136Config, config.Metrics, config.RateLimiter)
	if err != nil {
		return nil, err
	}

	h.access = access

	h.cache, err = provider.NewZoneCache(config.CacheConfig, config.Metrics, nil, h.getZones, h.getZoneState)
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *Handler) Release() {
	h.cache.Release()
}

// cache will fulfill this interface
func (h *Handler) GetZones() (provider.DNSHostedZones, error) {
	return h.cache.GetZones()
}

// GetZones for cache miss
func (h *Handler) getZones(cache provider.ZoneCache) (provider.DNSHostedZones, error) {
	rawZones := []dns.Envelope{}
	{
		f := func(zone dns.Envelope) (bool, error) {
			rawZones = append(rawZones, zone)
			return true, nil
		}
		err := h.access.ListZones(f)
		if err != nil {
			return nil, err
		}
	}

	zones := provider.DNSHostedZones{}

	for _, z := range rawZones {
		forwarded := []string{}
		f := func(r cloudflare.DNSRecord) (bool, error) {
			if r.Type == dns.RS_NS {
				name := r.Name
				if name != z.Name {
					forwarded = append(forwarded, name)
				}
			}
			return true, nil
		}
		err := h.access.ListRecords(z.ID, f)
		if err != nil {
			if strings.Contains(err.Error(), "403") {
				// It is possible to deny access to certain zones in the account
				// As a result, z zone should not be appended to the hosted zones
				continue
			} else {
				return nil, err
			}
		}

		hostedZone := provider.NewDNSHostedZone(h.ProviderType(), z.ID, z.Name, z.ID, forwarded, false)
		zones = append(zones, hostedZone)
	}

	return zones, nil
}

// cache will fulfill this interface
func (h *Handler) GetZoneState(zone provider.DNSHostedZone) (provider.DNSZoneState, error) {
	return h.cache.GetZoneState(zone)
}

// GetZoneState for cache miss
func (h *Handler) getZoneState(zone provider.DNSHostedZone, cache provider.ZoneCache) (provider.DNSZoneState, error) {
	state := raw.NewState()

	f := func(r cloudflare.DNSRecord) (bool, error) {
		a := (*Record)(&r)
		state.AddRecord(a)
		return true, nil
	}
	err := h.access.ListRecords(zone.Key(), f)
	if err != nil {
		return nil, err
	}
	state.CalculateDNSSets()
	return state, nil
}

func (h *Handler) ReportZoneStateConflict(zone provider.DNSHostedZone, err error) bool {
	return h.cache.ReportZoneStateConflict(zone, err)
}

func (h *Handler) ExecuteRequests(logger logger.LogContext, zone provider.DNSHostedZone, state provider.DNSZoneState, reqs []*provider.ChangeRequest) error {
	err := raw.ExecuteRequests(logger, &h.config, h.access, zone, state, reqs)
	h.cache.ApplyRequests(logger, err, zone, reqs)
	return err
}
