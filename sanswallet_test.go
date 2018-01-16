/*
	SansWallet is a BIP32, BIP44, BIP49 and BIP84 compatible hierarchical determinstic wallet
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
	// Seed : mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
	testSeedHex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

	// useful Test reference: https://iancoleman.io/bip39/
	// P2PK BIP44
	testP2PK0  = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
	testP2PK1  = "1Ak8PffB2meyfYnbXZR9EGfLfFZVpzJvQP"
	testP2PK10 = "146emAmGumhnsT9nPCALU2JWeS4koxfFRB"

	testP2PKHPriv = "xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb"
	testP2PKHPub  = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"

	// P2SH BIP49
	testP2SH0  = "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
	testP2SH1  = "3LtMnn87fqUeHBUG414p9CWwnoV6E2pNKS"
	testP2SH10 = "38mWd5D48ShYPJMZngtmxPQVYhQR5DGgfF"

	testP2SHPriv = "yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQeKTffhrHY79hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF"
	testP2SHPub  = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP"

	// P2WPKH BIP84
	testP2WPKH0  = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
	testP2WPKH1  = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
	testP2WPKH10 = "bc1qd30z5a5e50jtgx28rvt64483tq65r9pkj623wh"

	testP2WPKHPriv = "zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE"
	testP2WPKHPub  = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"

	testIsChangeAddress = false
	testIsTestnet       = false
)

func TestP2PKHKeyExport(t *testing.T) {
	seed, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Error(err.Error())
	}

	priv, err := GetExtPrvForP2PKHAccount(seed, 0, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if priv != testP2PKHPriv {
		t.Errorf("test extended P2PKH private key export is not expected value want\n%s \ngot \n%s", testP2PKHPriv, priv)
	}

	pub, err := GetExtPubForP2PKHAccount(seed, 0, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if pub != testP2PKHPub {
		t.Errorf("test extended P2PKH public key export is not expected value want\n%s \ngot \n%s", testP2PKHPub, pub)
	}
}

func TestP2SHKeyExport(t *testing.T) {
	seed, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Error(err.Error())
	}

	priv, err := GetExtPrvForP2SHAccount(seed, 0, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if priv != testP2SHPriv {
		t.Errorf("test extended P2SH private key export is not expected value want\n%s \ngot \n%s", testP2SHPriv, priv)
	}

	pub, err := GetExtPubForP2SHAccount(seed, 0, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if pub != testP2SHPub {
		t.Errorf("test extended P2SH public key export is not expected value want\n%s \ngot \n%s", testP2SHPub, pub)
	}
}

func TestP2WPKHKeyExport(t *testing.T) {
	seed, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Error(err.Error())
	}

	priv, err := GetExtPrvForP2WPKHAccount(seed, 0, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if priv != testP2WPKHPriv {
		t.Errorf("test extended P2WPKH private key export is not expected value want\n%s \ngot \n%s", testP2WPKHPriv, priv)
	}

	pub, err := GetExtPubForP2WPKHAccount(seed, 0, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if pub != testP2WPKHPub {
		t.Errorf("test extended P2WPKH public key export is not expected value want\n%s \ngot \n%s", testP2WPKHPub, pub)
	}

	np, err := GetP2WPKHAddressForIndex(pub, 0, false, false)
	if err != nil {
		t.Error(err.Error())
	}

	if np != testP2WPKH0 {
		t.Errorf("test extended P2WPKH public key did not result in expected address")
	}
}

func TestP2WPKHAddressGeneration(t *testing.T) {
	seed, err := hex.DecodeString(testSeedHex)
	if err != nil {
		t.Error(err.Error())
	}

	pk, err := GetExtPrvForP2WPKHAccount(seed, 0, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	address0, err := GetP2WPKHAddressForIndex(pk, 0, testIsChangeAddress, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if address0 != testP2WPKH0 {
		t.Errorf("test P2WPK address 0 is not expected value want %s got %s", testP2WPKH0, address0)
	}

	address1, err := GetP2WPKHAddressForIndex(pk, 1, testIsChangeAddress, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if address1 != testP2WPKH1 {
		t.Errorf("test P2WPK address 1 is not expected value want %s got %s", testP2WPKH1, address1)
	}

	address10, err := GetP2WPKHAddressForIndex(pk, 10, testIsChangeAddress, testIsTestnet)
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

	pk, err := GetExtPrvForP2SHAccount(seed, 0, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	address0, err := GetP2SHAddressForIndex(pk, 0, testIsChangeAddress, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if address0 != testP2SH0 {
		t.Errorf("test P2SH address 0 is not expected value want %s got %s", testP2SH0, address0)
	}

	address1, err := GetP2SHAddressForIndex(pk, 1, testIsChangeAddress, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if address1 != testP2SH1 {
		t.Errorf("test P2SH address 1 is not expected value want %s got %s", testP2SH1, address1)
	}

	address10, err := GetP2SHAddressForIndex(pk, 10, testIsChangeAddress, testIsTestnet)
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

	pk, err := GetExtPrvForP2PKHAccount(seed, 0, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	address0, err := GetP2PKHAddressForIndex(pk, 0, testIsChangeAddress, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if address0 != testP2PK0 {
		t.Errorf("test P2PKH address 0 is not expected value want %s got %s", testP2PK0, address0)
	}

	address1, err := GetP2PKHAddressForIndex(pk, 1, testIsChangeAddress, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if address1 != testP2PK1 {
		t.Errorf("test P2PKH address 1 is not expected value want %s got %s", testP2PK1, address1)
	}

	address10, err := GetP2PKHAddressForIndex(pk, 10, testIsChangeAddress, testIsTestnet)
	if err != nil {
		t.Error(err.Error())
	}

	if address10 != testP2PK10 {
		t.Errorf("test P2PKH address 10 is not expected value want %s got %s", testP2PK10, address10)
	}
}
