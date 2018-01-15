/*
	SansSeed is a BIP39 compatible implementation for generating mnemonic phrases and seed derivation
	Copyright (C) 2018  Sans Central

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package sanswallet

import (
	"encoding/hex"
	"testing"
)

const (
	// Seed
	testSeedHex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

	// useful Test reference: https://iancoleman.io/bip39/
	// P2PK
	testP2PK0  = "148CGtv7bwcC933EHtcDfzDQVneur1R8Y1"
	testP2PK1  = "1FQEcNEtCxvwonGfPkhPqtV2VvjTjVUPv4"
	testP2PK10 = "1AatH1T4wHYLLMMZ5qezGL45x2DZVRSyS2"

	// P2SH
	testP2SH0  = "3Mkk7sXeB9833KdU5yy9Y8Ev88W53c9FEH"
	testP2SH1  = "3BnbC5t8yMqhi8jhLVH71dW1yCpWoaAZyw"
	testP2SH10 = "3KPmr5JdcGrKSsBYXghErPDu452Sjyzfnw"

	// P2WPKH
	testP2WPKH0  = "bc1qyfztx0azgwhw8020yekzkl4j4q4ux8t926ft2y"
	testP2WPKH1  = "bc1qnhmtqhcm3v809let9kl0ps07zq4s2zyx48ulp4"
	testP2WPKH10 = "bc1qdys6jmjznxucxq6prkefcnuqt3xhk8qgr95ccq"

	// Extended key exports
	testPrivateKey = "xprv9zBMyndPhLXWLk29RpugWNgciJ3o6eDMDHwg79vPxccrV66XmEiF6x4voGKn3kDTX78Ph5h3PAM7699imc3T8P39qy9y9oi8X37zTEJrTgH"
	testPublicKey  = "xpub6DAiPJAHXi5oZE6cXrSgsWdMGKtHW6wCaWsGuYL1Wx9qMtRgJn2VekPQeZc1WwAoeuoytGozkCQnToL2PMw4deyhWGEu7Xou6gPYc1KqYuj"
)

func TestKeyExport(t *testing.T) {
	seed, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Error(err.Error())
	}

	priv, err := GetXPrivForAccount(seed, 0)
	if err != nil {
		t.Error(err.Error())
	}

	if priv != testPrivateKey {
		t.Errorf("test extended private key export is not expected value want %s got %s", testPrivateKey, priv)
	}

	pub, err := GetXPubKeyForAccount(seed, 0)
	if err != nil {
		t.Error(err.Error())
	}

	if pub != testPublicKey {
		t.Errorf("test extended public key export is not expected value want %s got %s", testPublicKey, pub)
	}
}

func TestP2WPKHAddressGeneration(t *testing.T) {
	seed, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Error(err.Error())
	}

	pk, err := GetXPrivForAccount(seed, 0)
	if err != nil {
		t.Error(err.Error())
	}

	address0, err := GetP2WPKHAddressForIndex(pk, 0)
	if err != nil {
		t.Error(err.Error())
	}

	if address0 != testP2WPKH0 {
		t.Errorf("test P2WPK address 0 is not expected value want %s got %s", testP2WPKH0, address0)
	}

	address1, err := GetP2WPKHAddressForIndex(pk, 1)
	if err != nil {
		t.Error(err.Error())
	}

	if address1 != testP2WPKH1 {
		t.Errorf("test P2WPK address 1 is not expected value want %s got %s", testP2WPKH1, address1)
	}

	address10, err := GetP2WPKHAddressForIndex(pk, 10)
	if err != nil {
		t.Error(err.Error())
	}

	if address10 != testP2WPKH10 {
		t.Errorf("test P2WPK address 10 is not expected value want %s got %s", testP2WPKH10, address10)
	}
}

func TestP2SHAddressGeneration(t *testing.T) {
	seed, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Error(err.Error())
	}

	pk, err := GetXPrivForAccount(seed, 0)
	if err != nil {
		t.Error(err.Error())
	}

	address0, err := GetP2SHAddressForIndex(pk, 0)
	if err != nil {
		t.Error(err.Error())
	}

	if address0 != testP2SH0 {
		t.Errorf("test P2SH address 0 is not expected value want %s got %s", testP2SH0, address0)
	}

	address1, err := GetP2SHAddressForIndex(pk, 1)
	if err != nil {
		t.Error(err.Error())
	}

	if address1 != testP2SH1 {
		t.Errorf("test P2SH address 1 is not expected value want %s got %s", testP2SH1, address1)
	}

	address10, err := GetP2SHAddressForIndex(pk, 10)
	if err != nil {
		t.Error(err.Error())
	}

	if address10 != testP2SH10 {
		t.Errorf("test P2SH address 10 is not expected value want %s got %s", testP2SH10, address10)
	}
}

func TestP2PKHAddressGeneration(t *testing.T) {
	seed, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Error(err.Error())
	}

	pk, err := GetXPrivForAccount(seed, 0)
	if err != nil {
		t.Error(err.Error())
	}

	address0, err := GetP2PKHAddressForIndex(pk, 0)
	if err != nil {
		t.Error(err.Error())
	}

	if address0 != testP2PK0 {
		t.Errorf("test P2PKH address 0 is not expected value want %s got %s", testP2PK0, address0)
	}

	address1, err := GetP2PKHAddressForIndex(pk, 1)
	if err != nil {
		t.Error(err.Error())
	}

	if address1 != testP2PK1 {
		t.Errorf("test P2PKH address 1 is not expected value want %s got %s", testP2PK1, address1)
	}

	address10, err := GetP2PKHAddressForIndex(pk, 10)
	if err != nil {
		t.Error(err.Error())
	}

	if address10 != testP2PK10 {
		t.Errorf("test P2PKH address 10 is not expected value want %s got %s", testP2PK10, address10)
	}
}
