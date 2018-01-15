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
