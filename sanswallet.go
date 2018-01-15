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
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"

	"github.com/sanscentral/sanswallet/keys"
	"github.com/sanscentral/sanswallet/network"
)

// GetXPrivForAccount returns extended private key for given account index
func GetXPrivForAccount(seed []byte, accountIndex uint32) (string, error) {
	m, err := keys.GetExtendedMasterPrivateKeyFromSeedBytes(seed, network.BTCMainnet)
	if err != nil {
		return "", err
	}

	return keys.GetBTCAccountKey(m, accountIndex, true)
}

// GetXPubKeyForAccount returns extended public key for given account index
func GetXPubKeyForAccount(seed []byte, accountIndex uint32) (string, error) {
	m, err := keys.GetExtendedMasterPrivateKeyFromSeedBytes(seed, network.BTCMainnet)
	if err != nil {
		return "", err
	}

	return keys.GetBTCAccountKey(m, accountIndex, false)
}

// GetP2WPKHAddressForIndex returns segwit bech32 address for BTC account extended key at given index
// P2WPKH pay-to-witness-public-key-hash is the shorter segwit form of P2PKH (newest address format at time of writing)
func GetP2WPKHAddressForIndex(accountKey string, index uint32, isChange bool) (string, error) {

	addt := keys.ExternalAddress
	if isChange {
		addt = keys.ChangeAddress
	}

	k, err := keys.GetBTCAccountAddressKey(accountKey, addt, index)
	if err != nil {
		return "", err
	}

	pk, err := k.ECPubKey()
	if err != nil {
		return "", err
	}

	keyHash := btcutil.Hash160(pk.SerializeCompressed())
	segAddr, err := btcutil.NewAddressWitnessPubKeyHash(keyHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}

	return segAddr.EncodeAddress(), nil
}

// GetP2SHAddressForIndex returns address for BTC account at given index
// P2SH ('3' prefixed addresses) pay-to-script-hash includes P2SH-wrapped segwit outputs
func GetP2SHAddressForIndex(accountKey string, index uint32, isChange bool) (string, error) {
	addt := keys.ExternalAddress
	if isChange {
		addt = keys.ChangeAddress
	}

	k, err := keys.GetBTCAccountAddressKey(accountKey, addt, index)
	if err != nil {
		return "", err
	}

	pk, err := k.ECPubKey()
	if err != nil {
		return "", err
	}
	keyHash := btcutil.Hash160(pk.SerializeCompressed())
	scriptSig, err := txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(keyHash).Script()
	if err != nil {
		return "", err
	}
	segAddr, err := btcutil.NewAddressScriptHash(scriptSig, &chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}
	return segAddr.EncodeAddress(), nil
}

// GetP2PKHAddressForIndex returns address for BTC account at given index
// P2PK ('1' prefixed addresses) origional pay-to-public-key
func GetP2PKHAddressForIndex(accountKey string, index uint32, isChange bool) (string, error) {
	addt := keys.ExternalAddress
	if isChange {
		addt = keys.ChangeAddress
	}

	k, err := keys.GetBTCAccountAddressKey(accountKey, addt, index)
	if err != nil {
		return "", err
	}

	a, err := k.Address(&chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}

	return a.EncodeAddress(), nil
}
