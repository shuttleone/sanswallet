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
	"fmt"
	"strconv"
)

// intToUint converts integer type to unsigned integer type
// as support for unsigned integers in GoMobile is currently missing
func intToUint32(i int) (uint32, error) {
	s := fmt.Sprintf("%d", i)
	ui, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(ui), nil
}
