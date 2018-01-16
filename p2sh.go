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
	"errors"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"

	"github.com/sanscentral/sanswallet/keys"
	"github.com/sanscentral/sanswallet/network"
)

var (
	// Version bytes of master public/private keys indicate what type of output script should be used.
	privP2WPKHinP2SHVer = [4]byte{0x04, 0x9d, 0x78, 0x78}
	pubP2WPKHinP2SHVer  = [4]byte{0x04, 0x9d, 0x7c, 0xb2}

	// possible prefixes for a P2SH key (Used for key validation)
	p2shHumanPre = map[string]bool{"ypub": true, "yprv": true}
)

// GetXPrivForP2SHAccount returns extended private key for BIP49 P2SH account
func GetXPrivForP2SHAccount(seed []byte, accountIndex int, testnet bool) (string, error) {
	index, err := intToUint32(accountIndex)
	if err != nil {
		return "", err
	}

	net := network.BTCMainnet
	if testnet {
		net = network.BTCTestnet
	}

	m, err := keys.GetExtendedMasterPrivateKeyFromSeedBytes(seed, net)
	if err != nil {
		return "", err
	}

	k, err := keys.GetBIP49AccountKey(m, index, true)
	if err != nil {
		return "", err
	}

	return hdkeychain.VersionedStringFromExtendedKeyString(k, privP2WPKHinP2SHVer)
}

// GetXPubForP2SHAccount returns extended public key for BIP49 P2SH account
func GetXPubForP2SHAccount(seed []byte, accountIndex int, testnet bool) (string, error) {
	index, err := intToUint32(accountIndex)
	if err != nil {
		return "", err
	}

	net := network.BTCMainnet
	if testnet {
		net = network.BTCTestnet
	}

	m, err := keys.GetExtendedMasterPrivateKeyFromSeedBytes(seed, net)
	if err != nil {
		return "", err
	}

	k, err := keys.GetBIP49AccountKey(m, index, false)
	return hdkeychain.VersionedStringFromExtendedKeyString(k, pubP2WPKHinP2SHVer)
}

// GetP2SHAddressForIndex returns address for BTC account at given index
// P2SH ('3' prefixed addresses) pay-to-script-hash includes P2WPKH-wrapped in P2SH segwit outputs (use BIP49 derived key)
func GetP2SHAddressForIndex(accountKey string, addressIndex int, isChange bool, testnet bool) (string, error) {
	validPre := p2shHumanPre[accountKey[:4]]
	if !validPre {
		return "", errors.New("Key does not start with a P2SH prefix")
	}

	index, err := intToUint32(addressIndex)
	if err != nil {
		return "", err
	}

	addt := keys.ExternalAddress
	if isChange {
		addt = keys.ChangeAddress
	}

	k, err := keys.GetAccountAddressKey(accountKey, addt, index)
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

	netParam := &chaincfg.MainNetParams
	if testnet {
		netParam = &chaincfg.TestNet3Params
	}

	segAddr, err := btcutil.NewAddressScriptHash(scriptSig, netParam)
	if err != nil {
		return "", err
	}
	return segAddr.EncodeAddress(), nil
}
