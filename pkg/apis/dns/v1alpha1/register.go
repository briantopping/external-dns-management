// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/gardener/external-dns-management/pkg/apis/dns"
)

const (
	Version   = "v1alpha1"
	GroupName = dns.GroupName

	DNSProviderKind         = "DNSProvider"
	DNSEntryKind            = "DNSEntry"
	DNSAnnotationKind       = "DNSAnnotation"
	DNSHostedZonePolicyKind = "DNSHostedZonePolicy"
)

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: dns.GroupName, Version: Version}

// Kind takes an unqualified kind and returns back a Group qualified GroupKind
func Kind(kind string) schema.GroupKind {
	return SchemeGroupVersion.WithKind(kind).GroupKind()
}

// Resource takes an unqualified resources and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

// Adds the list of known types to Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&DNSProvider{},
		&DNSProviderList{},
		&DNSEntry{},
		&DNSEntryList{},
		&DNSAnnotation{},
		&DNSAnnotationList{},
		&DNSHostedZonePolicy{},
		&DNSHostedZonePolicyList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
