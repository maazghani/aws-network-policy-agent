package fqdn

import "golang.org/x/sys/unix"

// BootClock includes machine suspension, unlike Go's monotonic time component.
// The BPF datapath must use bpf_ktime_get_boot_ns, not bpf_ktime_get_ns.
type BootClock struct{}

func (BootClock) Now() (uint64, error) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return 0, err
	}
	return uint64(now.Sec)*1_000_000_000 + uint64(now.Nsec), nil
}
