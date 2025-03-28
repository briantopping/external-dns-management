// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0
// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeDNSOwners implements DNSOwnerInterface
type FakeDNSOwners struct {
	Fake *FakeDnsV1alpha1
	ns   string
}

var dnsownersResource = v1alpha1.SchemeGroupVersion.WithResource("dnsowners")

var dnsownersKind = v1alpha1.SchemeGroupVersion.WithKind("DNSOwner")

// Get takes name of the dNSOwner, and returns the corresponding dNSOwner object, and an error if there is any.
func (c *FakeDNSOwners) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.DNSOwner, err error) {
	emptyResult := &v1alpha1.DNSOwner{}
	obj, err := c.Fake.
		Invokes(testing.NewGetActionWithOptions(dnsownersResource, c.ns, name, options), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.DNSOwner), err
}

// List takes label and field selectors, and returns the list of DNSOwners that match those selectors.
func (c *FakeDNSOwners) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.DNSOwnerList, err error) {
	emptyResult := &v1alpha1.DNSOwnerList{}
	obj, err := c.Fake.
		Invokes(testing.NewListActionWithOptions(dnsownersResource, dnsownersKind, c.ns, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.DNSOwnerList{ListMeta: obj.(*v1alpha1.DNSOwnerList).ListMeta}
	for _, item := range obj.(*v1alpha1.DNSOwnerList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested dNSOwners.
func (c *FakeDNSOwners) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchActionWithOptions(dnsownersResource, c.ns, opts))

}

// Create takes the representation of a dNSOwner and creates it.  Returns the server's representation of the dNSOwner, and an error, if there is any.
func (c *FakeDNSOwners) Create(ctx context.Context, dNSOwner *v1alpha1.DNSOwner, opts v1.CreateOptions) (result *v1alpha1.DNSOwner, err error) {
	emptyResult := &v1alpha1.DNSOwner{}
	obj, err := c.Fake.
		Invokes(testing.NewCreateActionWithOptions(dnsownersResource, c.ns, dNSOwner, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.DNSOwner), err
}

// Update takes the representation of a dNSOwner and updates it. Returns the server's representation of the dNSOwner, and an error, if there is any.
func (c *FakeDNSOwners) Update(ctx context.Context, dNSOwner *v1alpha1.DNSOwner, opts v1.UpdateOptions) (result *v1alpha1.DNSOwner, err error) {
	emptyResult := &v1alpha1.DNSOwner{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateActionWithOptions(dnsownersResource, c.ns, dNSOwner, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.DNSOwner), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeDNSOwners) UpdateStatus(ctx context.Context, dNSOwner *v1alpha1.DNSOwner, opts v1.UpdateOptions) (result *v1alpha1.DNSOwner, err error) {
	emptyResult := &v1alpha1.DNSOwner{}
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceActionWithOptions(dnsownersResource, "status", c.ns, dNSOwner, opts), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.DNSOwner), err
}

// Delete takes name of the dNSOwner and deletes it. Returns an error if one occurs.
func (c *FakeDNSOwners) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(dnsownersResource, c.ns, name, opts), &v1alpha1.DNSOwner{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeDNSOwners) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionActionWithOptions(dnsownersResource, c.ns, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.DNSOwnerList{})
	return err
}

// Patch applies the patch and returns the patched dNSOwner.
func (c *FakeDNSOwners) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.DNSOwner, err error) {
	emptyResult := &v1alpha1.DNSOwner{}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceActionWithOptions(dnsownersResource, c.ns, name, pt, data, opts, subresources...), emptyResult)

	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.DNSOwner), err
}
