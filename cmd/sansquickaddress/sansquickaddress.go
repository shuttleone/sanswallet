/*
	SansWallet is a BIP32, BIP44, BIP49 and BIP84 compatible hierarchical determinstic wallet
	Copyright (C) 2018 Sans Central

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

package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sanscentral/sanswallet"

	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	seed         = kingpin.Flag("seed", "root seed in hexadecimal form").Default().Short('s').String()
	addressType  = kingpin.Flag("type", "address type must be 'p2sh','p2pkh' or 'p2wpkh'").Default("p2pkh").Short('t').String()
	addressIndex = kingpin.Flag("index", "address index").Default("0").Short('i').Int()
	count        = kingpin.Flag("count", "number of addresses to retrieve starting from index").Default("1").Short('c').Int()
	testnet      = kingpin.Flag("testnet", "use testnet").Default("false").Short('d').Bool()
	prvKey       = kingpin.Flag("pub", "prints the address private key").Default("false").Short('x').Bool()
	pubKey       = kingpin.Flag("prv", "prints the address public key").Default("false").Short('p').Bool()
)

func main() {
	kingpin.Version("1.0.0")
	kingpin.Parse()

	seed, err := hex.DecodeString(*seed)
	if err != nil {
		panic(err)
	}

	prv := ""
	pub := ""
	address := []string{}
	switch strings.ToLower(*addressType) {
	case "p2pkh":
		var err error
		prv, err = sanswallet.GetExtPrvForP2PKHAccount(seed, 0, *testnet)
		if err != nil {
			panic(err)
		}
		pub, err = sanswallet.GetExtPubForP2PKHAccount(seed, 0, *testnet)
		if err != nil {
			panic(err)
		}

		for index := 0; index < *count; index++ {
			a := ""
			a, err = sanswallet.GetP2PKHAddressForIndex(prv, *addressIndex+index, false, *testnet)
			if err != nil {
				panic(err)
			}
			address = append(address, a)
		}

	case "p2sh":
		var err error
		prv, err = sanswallet.GetExtPrvForP2SHAccount(seed, 0, *testnet)
		if err != nil {
			panic(err)
		}
		pub, err = sanswallet.GetExtPubForP2SHAccount(seed, 0, *testnet)
		if err != nil {
			panic(err)
		}

		for index := 0; index < *count; index++ {
			a := ""
			a, err = sanswallet.GetP2SHAddressForIndex(prv, *addressIndex+index, false, *testnet)
			if err != nil {
				panic(err)
			}
			address = append(address, a)
		}

	case "p2wpkh":
		var err error
		prv, err = sanswallet.GetExtPrvForP2WPKHAccount(seed, 0, *testnet)
		if err != nil {
			panic(err)
		}
		pub, err = sanswallet.GetExtPubForP2WPKHAccount(seed, 0, *testnet)
		if err != nil {
			panic(err)
		}

		for index := 0; index < *count; index++ {
			a := ""
			a, err = sanswallet.GetP2WPKHAddressForIndex(prv, *addressIndex+index, false, *testnet)
			if err != nil {
				panic(err)
			}
			address = append(address, a)
		}
	}

	if *prvKey {
		fmt.Printf("Private Key is:%s\n", prv)
	}

	if *pubKey {
		fmt.Printf("Public Key is:%s\n", pub)
	}

	for i, s := range address {
		fmt.Printf("%d.	%s\n", i+*addressIndex, s)
	}
}
