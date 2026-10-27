package pcapnet

import "fmt"

const (
	// outerIPv4HeaderSize is the standard IPv4 header size
	// without additional IPv4 options.
	outerIPv4HeaderSize = 20

	// outerUDPHeaderSize is the UDP transport header size.
	outerUDPHeaderSize = 8

	// minimumInnerIPv4MTU is the minimum IPv4 MTU
	// accepted by this package.
	minimumInnerIPv4MTU = 576
)

// MaxInnerMTU calculates the maximum inner IPv4 packet size
// that can fit within a physical interface's IP MTU.
//
// extraOverhead accounts for optional tunnel framing,
// authentication tags, or other encapsulation overhead.
//
// Ethernet headers are excluded from this calculation.
func MaxInnerMTU(
	physicalMTU uint32,
	extraOverhead uint32,
) (uint32, error) {
	// Validate the physical interface MTU.
	if physicalMTU < minimumInnerIPv4MTU {
		return 0, fmt.Errorf("physical MTU is too small")
	}

	// Calculate the outer IPv4 and UDP overhead.
	const baseOverhead = outerIPv4HeaderSize + outerUDPHeaderSize

	// Ensure the overhead does not exceed the available MTU.
	if extraOverhead > physicalMTU-baseOverhead {
		return 0, fmt.Errorf("encapsulation overhead exceeds physical MTU")
	}

	// Calculate the remaining space for the inner packet.
	innerMTU := physicalMTU - baseOverhead - extraOverhead

	// Ensure the calculated MTU satisfies our IPv4 minimum.
	if innerMTU < minimumInnerIPv4MTU {
		return 0, fmt.Errorf(
			"inner MTU %d is below minimum %d",
			innerMTU,
			minimumInnerIPv4MTU,
		)
	}

	return innerMTU, nil
}

// ValidateInnerMTU verifies that a configured virtual MTU
// fits within the physical interface's MTU.
func ValidateInnerMTU(
	virtualMTU uint32,
	physicalMTU uint32,
	extraOverhead uint32,
) error {
	// Calculate the maximum supported virtual MTU.
	maximum, err := MaxInnerMTU(physicalMTU, extraOverhead)
	if err != nil {
		return err
	}

	// Reject virtual MTUs that exceed the available space.
	if virtualMTU > maximum {
		return fmt.Errorf(
			"virtual MTU %d exceeds maximum %d",
			virtualMTU,
			maximum,
		)
	}

	// Reject virtual MTUs below our minimum.
	if virtualMTU < minimumInnerIPv4MTU {
		return fmt.Errorf(
			"virtual MTU %d is below minimum %d",
			virtualMTU,
			minimumInnerIPv4MTU,
		)
	}

	return nil
}
