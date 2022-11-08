// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

/*
 * Ory Kratos API
 *
 * Documentation for all public and administrative Ory Kratos APIs. Public and administrative APIs are exposed on different ports. Public APIs can face the public internet without any protection while administrative APIs should never be exposed without prior authorization. To protect the administative API port you should use something like Nginx, Ory Oathkeeper, or any other technology capable of authorizing incoming requests.
 *
 * API version:
 * Contact: hi@ory.sh
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"encoding/json"
	"time"
)

// SelfServiceRecoveryLink struct for SelfServiceRecoveryLink
type SelfServiceRecoveryLink struct {
	// Recovery Link Expires At  The timestamp when the recovery link expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// Recovery Link  This link can be used to recover the account.
	RecoveryLink string `json:"recovery_link"`
}

// NewSelfServiceRecoveryLink instantiates a new SelfServiceRecoveryLink object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSelfServiceRecoveryLink(recoveryLink string) *SelfServiceRecoveryLink {
	this := SelfServiceRecoveryLink{}
	this.RecoveryLink = recoveryLink
	return &this
}

// NewSelfServiceRecoveryLinkWithDefaults instantiates a new SelfServiceRecoveryLink object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSelfServiceRecoveryLinkWithDefaults() *SelfServiceRecoveryLink {
	this := SelfServiceRecoveryLink{}
	return &this
}

// GetExpiresAt returns the ExpiresAt field value if set, zero value otherwise.
func (o *SelfServiceRecoveryLink) GetExpiresAt() time.Time {
	if o == nil || o.ExpiresAt == nil {
		var ret time.Time
		return ret
	}
	return *o.ExpiresAt
}

// GetExpiresAtOk returns a tuple with the ExpiresAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SelfServiceRecoveryLink) GetExpiresAtOk() (*time.Time, bool) {
	if o == nil || o.ExpiresAt == nil {
		return nil, false
	}
	return o.ExpiresAt, true
}

// HasExpiresAt returns a boolean if a field has been set.
func (o *SelfServiceRecoveryLink) HasExpiresAt() bool {
	if o != nil && o.ExpiresAt != nil {
		return true
	}

	return false
}

// SetExpiresAt gets a reference to the given time.Time and assigns it to the ExpiresAt field.
func (o *SelfServiceRecoveryLink) SetExpiresAt(v time.Time) {
	o.ExpiresAt = &v
}

// GetRecoveryLink returns the RecoveryLink field value
func (o *SelfServiceRecoveryLink) GetRecoveryLink() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.RecoveryLink
}

// GetRecoveryLinkOk returns a tuple with the RecoveryLink field value
// and a boolean to check if the value has been set.
func (o *SelfServiceRecoveryLink) GetRecoveryLinkOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.RecoveryLink, true
}

// SetRecoveryLink sets field value
func (o *SelfServiceRecoveryLink) SetRecoveryLink(v string) {
	o.RecoveryLink = v
}

func (o SelfServiceRecoveryLink) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.ExpiresAt != nil {
		toSerialize["expires_at"] = o.ExpiresAt
	}
	if true {
		toSerialize["recovery_link"] = o.RecoveryLink
	}
	return json.Marshal(toSerialize)
}

type NullableSelfServiceRecoveryLink struct {
	value *SelfServiceRecoveryLink
	isSet bool
}

func (v NullableSelfServiceRecoveryLink) Get() *SelfServiceRecoveryLink {
	return v.value
}

func (v *NullableSelfServiceRecoveryLink) Set(val *SelfServiceRecoveryLink) {
	v.value = val
	v.isSet = true
}

func (v NullableSelfServiceRecoveryLink) IsSet() bool {
	return v.isSet
}

func (v *NullableSelfServiceRecoveryLink) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSelfServiceRecoveryLink(val *SelfServiceRecoveryLink) *NullableSelfServiceRecoveryLink {
	return &NullableSelfServiceRecoveryLink{value: val, isSet: true}
}

func (v NullableSelfServiceRecoveryLink) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSelfServiceRecoveryLink) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
