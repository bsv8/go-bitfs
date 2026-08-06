package arbitrated_pool

import "fmt"

type FeeSatPerKB uint64

func feeSat(size int, rate FeeSatPerKB) (uint64, error) {
	if size < 0 {
		return 0, fmt.Errorf("negative transaction size")
	}
	if size == 0 || rate == 0 {
		return 0, nil
	}
	if uint64(size) > ^uint64(0)/uint64(rate) {
		return 0, fmt.Errorf("transaction fee overflow")
	}
	value := uint64(size) * uint64(rate)
	if value > ^uint64(0)-999 {
		return 0, fmt.Errorf("transaction fee overflow")
	}
	return (value + 999) / 1000, nil
}

func ArbitratedPoolFeeSat(size int, rate FeeSatPerKB) (uint64, error) { return feeSat(size, rate) }
