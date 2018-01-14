package network

// Network references a distributed network endpoint
type Network int16

const (
	// BTCTestnet Bitcoin test network (3)
	BTCTestnet Network = 0

	// BTCMainnet Bitcoin main network
	BTCMainnet Network = 1
)
