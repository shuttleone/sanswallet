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
	testSeedHex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"

	// Test reference: https://iancoleman.io/bip39/
	testSeedHex2             = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
	testSeedHex2ExpectedPriv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"

	// P2PK
	testP2PK0  = "148CGtv7bwcC933EHtcDfzDQVneur1R8Y1"
	testP2PK1  = "1FQEcNEtCxvwonGfPkhPqtV2VvjTjVUPv4"
	testP2PK10 = "1AatH1T4wHYLLMMZ5qezGL45x2DZVRSyS2"

	// P2SH
	testP2SH0  = "148CGtv7bwcC933EHtcDfzDQVneur1R8Y1"
	testP2SH1  = "1FQEcNEtCxvwonGfPkhPqtV2VvjTjVUPv4"
	testP2SH10 = "1AatH1T4wHYLLMMZ5qezGL45x2DZVRSyS2"

	// P2WPKH
	testP2WPKH0  = "148CGtv7bwcC933EHtcDfzDQVneur1R8Y1"
	testP2WPKH1  = "1FQEcNEtCxvwonGfPkhPqtV2VvjTjVUPv4"
	testP2WPKH10 = "1AatH1T4wHYLLMMZ5qezGL45x2DZVRSyS2"
)

func TestSeed2Export(t *testing.T) {
	mb, err := hex.DecodeString(testSeedHex2)
	if err != nil {
		t.Error(err.Error())
	}
	s, err := GetXPrivForSeed(mb)
	if s != testSeedHex2ExpectedPriv {
		t.Errorf("exported priv is not expected value want %s got %s", testSeedHex2ExpectedPriv, s)
	}
}

func TestP2WPKHAddressGeneration(t *testing.T) {
	mb, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Error(err.Error())
	}

	address0, err := GetP2WPKHAddressForAccountAtIndex(mb, 0, 0)
	if err != nil {
		t.Error(err.Error())
	}

	if address0 != testP2WPKH0 {
		t.Errorf("test P2SH address 0 is not expected value want %s got %s", testP2WPKH0, address0)
	}

	address1, err := GetP2WPKHAddressForAccountAtIndex(mb, 0, 1)
	if err != nil {
		t.Error(err.Error())
	}

	if address1 != testP2WPKH1 {
		t.Errorf("test P2SH address 1 is not expected value want %s got %s", testP2WPKH1, address1)
	}

	address10, err := GetP2WPKHAddressForAccountAtIndex(mb, 0, 10)
	if err != nil {
		t.Error(err.Error())
	}

	if address10 != testP2WPKH10 {
		t.Errorf("test P2SH address 10 is not expected value want %s got %s", testP2WPKH10, address10)
	}
}

func TestP2SHAddressGeneration(t *testing.T) {
	mb, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Error(err.Error())
	}

	address0, err := GetP2SHAddressForAccountAtIndex(mb, 0, 0)
	if err != nil {
		t.Error(err.Error())
	}

	if address0 != testP2SH0 {
		t.Errorf("test P2SH address 0 is not expected value want %s got %s", testP2SH0, address0)
	}

	address1, err := GetP2SHAddressForAccountAtIndex(mb, 0, 1)
	if err != nil {
		t.Error(err.Error())
	}

	if address1 != testP2SH1 {
		t.Errorf("test P2SH address 1 is not expected value want %s got %s", testP2SH1, address1)
	}

	address10, err := GetP2SHAddressForAccountAtIndex(mb, 0, 10)
	if err != nil {
		t.Error(err.Error())
	}

	if address10 != testP2SH10 {
		t.Errorf("test P2SH address 10 is not expected value want %s got %s", testP2SH10, address10)
	}
}

func TestP2PKHAddressGeneration(t *testing.T) {
	mb, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Error(err.Error())
	}

	address0, err := GetP2PKHAddressForAccountAtIndex(mb, 0, 0)
	if err != nil {
		t.Error(err.Error())
	}

	if address0 != testP2PK0 {
		t.Errorf("test P2PKH address 0 is not expected value want %s got %s", testP2PK0, address0)
	}

	address1, err := GetP2PKHAddressForAccountAtIndex(mb, 0, 1)
	if err != nil {
		t.Error(err.Error())
	}

	if address1 != testP2PK1 {
		t.Errorf("test P2PKH address 1 is not expected value want %s got %s", testP2PK1, address1)
	}

	address10, err := GetP2PKHAddressForAccountAtIndex(mb, 0, 10)
	if err != nil {
		t.Error(err.Error())
	}

	if address10 != testP2PK10 {
		t.Errorf("test P2PKH address 10 is not expected value want %s got %s", testP2PK10, address10)
	}
}
