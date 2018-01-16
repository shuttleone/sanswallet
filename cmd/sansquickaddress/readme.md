# SansQuickAddress

A command-line tool to quickly generate a bitcoin addresses from a hex seed
All generated seeds are on account level zero with the index set from command input (m/44'/0'/0'/0)

### Usage
```
usage: sansquickaddress [<flags>]

Flags:
      --help          Show context-sensitive help (also try --help-long and --help-man).
  -s, --seed=SEED     root seed in hexadecimal form
  -t, --type="p2pkh"  address type must be 'p2sh','p2pkh' or 'p2wpkh'
  -i, --index=0       address index
  -c, --count=1       number of addresses to retrieve starting from index
  -d, --testnet       use testnet
  -x, --pub           prints the address private key
  -p, --prv           prints the address public key
      --version       Show application version.

Example: Return 1st address for seed
$ ./sansquickaddress -s 5eb00bbddcf069084889ddcf069084889ddcf069084889ddcf06908488

Example: Return 20 address and public + private keys for seed 
$ ./sansquickaddress --pub --prv -c 20 -s 5eb00bbddcf069084889ddcf069084889ddcf069084889ddcf06908488

Example: Return two P2WPKH address for seed 
$ ./sansquickaddress --type p2wpkh --count 2 --seed 5eb00bbddcf069084889ddcf069084889ddcf069084889ddcf06908488
```

## Contact

contact@sanscentral.org ([PGP](../../resources/publickey.contact@sanscentral.org.asc))

## License

![AGPLv3 Logo](../../resources/agplv3-155x51.png)

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
