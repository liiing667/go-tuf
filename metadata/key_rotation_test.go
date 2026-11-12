// Copyright 2024 The Update Framework Authors
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
// limitations under the License
//
// SPDX-License-Identifier: Apache-2.0
//

package metadata

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func rotationTestKey(publicKey string) *Key {
	return &Key{
		Type:   KeyTypeEd25519,
		Scheme: KeySchemeEd25519,
		Value:  KeyVal{PublicKey: publicKey},
	}
}

// rotationCollidingKey returns a key whose cached ID is the same as base's ID,
// but whose public key material is different.
func rotationCollidingKey(t *testing.T, base *Key) *Key {
	t.Helper()

	if _, err := base.ID(); err != nil {
		t.Fatal(err)
	}
	collision := *base
	collision.Value.PublicKey = strings.Repeat("b", len(base.Value.PublicKey))
	return &collision
}

func TestKeyRotationRootConflictAtomicity(t *testing.T) {
	root := Root(fixedExpire)
	key := rotationTestKey(strings.Repeat("a", 64))
	collision := rotationCollidingKey(t, key)

	err := root.Signed.AddKey(key, ROOT)
	assert.NoError(t, err)

	roleKeyIDs := slices.Clone(root.Signed.Roles[ROOT].KeyIDs)
	keys := maps.Clone(root.Signed.Keys)

	err = root.Signed.AddKey(collision, ROOT)
	assert.ErrorIs(t, err, &ErrValue{})
	assert.ErrorContains(t, err, "already exists")
	assert.Equal(t, roleKeyIDs, root.Signed.Roles[ROOT].KeyIDs)
	assert.Equal(t, keys, root.Signed.Keys)
	assert.Same(t, key, root.Signed.Keys[key.id])

	snapshotKeyIDs := slices.Clone(root.Signed.Roles[SNAPSHOT].KeyIDs)
	err = root.Signed.AddKey(collision, SNAPSHOT)
	assert.ErrorIs(t, err, &ErrValue{})
	assert.Equal(t, snapshotKeyIDs, root.Signed.Roles[SNAPSHOT].KeyIDs)
	assert.Equal(t, keys, root.Signed.Keys)

	// Re-adding the same key is idempotent, and the stored key is not replaced.
	err = root.Signed.AddKey(key, ROOT)
	assert.NoError(t, err)
	assert.Equal(t, roleKeyIDs, root.Signed.Roles[ROOT].KeyIDs)
	assert.Equal(t, keys, root.Signed.Keys)
	assert.Same(t, key, root.Signed.Keys[key.id])

	// The same key can still be added to a role that does not use it yet.
	err = root.Signed.AddKey(key, TARGETS)
	assert.NoError(t, err)
	assert.Contains(t, root.Signed.Roles[TARGETS].KeyIDs, key.id)
	assert.Same(t, key, root.Signed.Keys[key.id])

	_, err = root.Signed.MarshalJSON()
	assert.NoError(t, err)
	err = root.VerifyDelegate(ROOT, root)
	assert.ErrorIs(t, err, &ErrUnsignedMetadata{})
}

func TestKeyRotationTargetsConflictAtomicity(t *testing.T) {
	targets := Targets(fixedExpire)
	targets.Signed.Delegations = &Delegations{
		Keys: map[string]*Key{},
		Roles: []DelegatedRole{
			{Name: "role1", KeyIDs: []string{}, Threshold: 1},
			{Name: "role2", KeyIDs: []string{}, Threshold: 1},
		},
	}

	key := rotationTestKey(strings.Repeat("a", 64))
	collision := rotationCollidingKey(t, key)

	err := targets.Signed.AddKey(key, "role1")
	assert.NoError(t, err)

	role1KeyIDs := slices.Clone(targets.Signed.Delegations.Roles[0].KeyIDs)
	role2KeyIDs := slices.Clone(targets.Signed.Delegations.Roles[1].KeyIDs)
	keys := maps.Clone(targets.Signed.Delegations.Keys)

	err = targets.Signed.AddKey(collision, "role2")
	assert.ErrorIs(t, err, &ErrValue{})
	assert.ErrorContains(t, err, "already exists")
	assert.Equal(t, role1KeyIDs, targets.Signed.Delegations.Roles[0].KeyIDs)
	assert.Equal(t, role2KeyIDs, targets.Signed.Delegations.Roles[1].KeyIDs)
	assert.Equal(t, keys, targets.Signed.Delegations.Keys)
	assert.Same(t, key, targets.Signed.Delegations.Keys[key.id])

	err = targets.Signed.AddKey(collision, "role1")
	assert.ErrorIs(t, err, &ErrValue{})
	assert.Equal(t, role1KeyIDs, targets.Signed.Delegations.Roles[0].KeyIDs)
	assert.Equal(t, keys, targets.Signed.Delegations.Keys)

	// Re-adding the same key is idempotent.
	err = targets.Signed.AddKey(key, "role1")
	assert.NoError(t, err)
	assert.Equal(t, role1KeyIDs, targets.Signed.Delegations.Roles[0].KeyIDs)
	assert.Equal(t, keys, targets.Signed.Delegations.Keys)
	assert.Same(t, key, targets.Signed.Delegations.Keys[key.id])

	// The same key can be added to another delegated role.
	err = targets.Signed.AddKey(key, "role2")
	assert.NoError(t, err)
	assert.Contains(t, targets.Signed.Delegations.Roles[1].KeyIDs, key.id)
	assert.Same(t, key, targets.Signed.Delegations.Keys[key.id])

	_, err = targets.Signed.MarshalJSON()
	assert.NoError(t, err)
}

func TestKeyRotationSuccinctRolesConflictAtomicity(t *testing.T) {
	targets := Targets(fixedExpire)
	targets.Signed.Delegations = &Delegations{
		Keys: map[string]*Key{},
		SuccinctRoles: &SuccinctRoles{
			KeyIDs:     []string{},
			Threshold:  1,
			BitLength:  8,
			NamePrefix: "role",
		},
	}

	key := rotationTestKey(strings.Repeat("a", 64))
	collision := rotationCollidingKey(t, key)

	err := targets.Signed.AddKey(key, "role")
	assert.NoError(t, err)

	keyIDs := slices.Clone(targets.Signed.Delegations.SuccinctRoles.KeyIDs)
	keys := maps.Clone(targets.Signed.Delegations.Keys)

	err = targets.Signed.AddKey(collision, "role")
	assert.ErrorIs(t, err, &ErrValue{})
	assert.ErrorContains(t, err, "already exists")
	assert.Equal(t, keyIDs, targets.Signed.Delegations.SuccinctRoles.KeyIDs)
	assert.Equal(t, keys, targets.Signed.Delegations.Keys)
	assert.Same(t, key, targets.Signed.Delegations.Keys[key.id])

	err = targets.Signed.AddKey(key, "role")
	assert.NoError(t, err)
	assert.Equal(t, keyIDs, targets.Signed.Delegations.SuccinctRoles.KeyIDs)
	assert.Equal(t, keys, targets.Signed.Delegations.Keys)
	assert.Same(t, key, targets.Signed.Delegations.Keys[key.id])
}

func TestKeyRotationNilKeyStoreAtomicity(t *testing.T) {
	key := rotationTestKey(strings.Repeat("a", 64))

	root := Root(fixedExpire)
	root.Signed.Keys = nil
	roleKeyIDs := slices.Clone(root.Signed.Roles[ROOT].KeyIDs)

	err := root.Signed.AddKey(key, ROOT)
	assert.ErrorIs(t, err, &ErrValue{})
	assert.Equal(t, roleKeyIDs, root.Signed.Roles[ROOT].KeyIDs)
	assert.Nil(t, root.Signed.Keys)

	targets := Targets(fixedExpire)
	targets.Signed.Delegations = &Delegations{
		Roles: []DelegatedRole{
			{Name: "role1", KeyIDs: []string{}, Threshold: 1},
		},
	}
	roleKeyIDs = slices.Clone(targets.Signed.Delegations.Roles[0].KeyIDs)

	err = targets.Signed.AddKey(key, "role1")
	assert.ErrorIs(t, err, &ErrValue{})
	assert.Equal(t, roleKeyIDs, targets.Signed.Delegations.Roles[0].KeyIDs)
	assert.Nil(t, targets.Signed.Delegations.Keys)
}

func TestKeyRotationSerializationFailureAtomicity(t *testing.T) {
	root := Root(fixedExpire)
	key := rotationTestKey(strings.Repeat("a", 64))
	key.UnrecognizedFields = map[string]any{"invalid": make(chan int)}

	roleKeyIDs := slices.Clone(root.Signed.Roles[ROOT].KeyIDs)
	keys := maps.Clone(root.Signed.Keys)

	err := root.Signed.AddKey(key, ROOT)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, &ErrValue{})
	assert.Equal(t, roleKeyIDs, root.Signed.Roles[ROOT].KeyIDs)
	assert.Equal(t, keys, root.Signed.Keys)
}
