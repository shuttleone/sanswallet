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

	"github.com/sanscentral/sanswallet/keys"
	"github.com/sanscentral/sanswallet/network"
)

var (
	// possible prefixes for a P2PKH key (Used for key validation)
	p2pkhHumanPre = map[string]bool{"xpub": true, "xprv": true}
)

// GetExtPrvForP2PKHAccount returns extended private key for BIP44 P2PKH account
func GetExtPrvForP2PKHAccount(seed []byte, accountIndex int, testnet bool) (string, error) {
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

	// Note: version prefix is unchanged for P2PKH since it matches network params

	return keys.GetBIP44AccountKey(m, index, true)
}

// GetExtPubForP2PKHAccount returns extended public key for BIP44 P2PKH account
func GetExtPubForP2PKHAccount(seed []byte, accountIndex int, testnet bool) (string, error) {
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

	// Note: version prefix is unchanged for P2PKH since it matches network params

	return keys.GetBIP44AccountKey(m, index, false)
}

// GetP2PKHAddressForIndex returns address for BTC account at given index
// P2PK ('1' prefixed addresses) origional pay-to-public-key (use BIP44 derived key)
func GetP2PKHAddressForIndex(accountKey string, addressIndex int, isChange bool, testnet bool) (string, error) {
	validPre := p2pkhHumanPre[accountKey[:4]]
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

	netParam := &chaincfg.MainNetParams
	if testnet {
		netParam = &chaincfg.TestNet3Params
	}

	a, err := k.Address(netParam)
	if err != nil {
		return "", err
	}

	return a.EncodeAddress(), nil
}
