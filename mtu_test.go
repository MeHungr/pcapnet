package pcapnet

import "testing"

// TestMaxInnerMTU verifies that outer protocol headers
// and additional overhead are subtracted correctly.
func TestMaxInnerMTU(t *testing.T) {
	// Define MTU calculation scenarios.
	tests := []struct {
		name          string
		physicalMTU   uint32
		extraOverhead uint32
		want          uint32
		wantErr       bool
	}{
		{
			name:        "standard Ethernet",
			physicalMTU: 1500,
			want:        1472,
		},
		{
			name:          "additional framing overhead",
			physicalMTU:   1500,
			extraOverhead: 32,
			want:          1440,
		},
		{
			name:        "jumbo MTU",
			physicalMTU: 9000,
			want:        8972,
		},
		{
			name:        "physical MTU too small",
			physicalMTU: 500,
			wantErr:     true,
		},
		{
			name:          "overhead exceeds available space",
			physicalMTU:   1500,
			extraOverhead: 1490,
			wantErr:       true,
		},
		{
			name:          "inner MTU below minimum",
			physicalMTU:   600,
			extraOverhead: 20,
			wantErr:       true,
		},
	}

	// Execute every MTU calculation scenario.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Calculate the maximum available inner MTU.
			got, err := MaxInnerMTU(
				tt.physicalMTU,
				tt.extraOverhead,
			)

			// Verify whether an error was expected.
			if (err != nil) != tt.wantErr {
				t.Fatalf(
					"MaxInnerMTU() error = %v, wantErr = %v",
					err,
					tt.wantErr,
				)
			}

			if tt.wantErr {
				return
			}

			// Verify the calculated MTU.
			if got != tt.want {
				t.Errorf("MTU = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestValidateInnerMTU verifies that configured virtual
// MTUs fit within the physical network MTU.
func TestValidateInnerMTU(t *testing.T) {
	// Define valid and invalid virtual MTU scenarios.
	tests := []struct {
		name          string
		virtualMTU    uint32
		physicalMTU   uint32
		extraOverhead uint32
		wantErr       bool
	}{
		{
			name:        "default virtual MTU",
			virtualMTU:  1200,
			physicalMTU: 1500,
		},
		{
			name:        "maximum virtual MTU",
			virtualMTU:  1472,
			physicalMTU: 1500,
		},
		{
			name:        "virtual MTU too large",
			virtualMTU:  1480,
			physicalMTU: 1500,
			wantErr:     true,
		},
		{
			name:        "virtual MTU too small",
			virtualMTU:  500,
			physicalMTU: 1500,
			wantErr:     true,
		},
		{
			name:          "additional overhead",
			virtualMTU:    1450,
			physicalMTU:   1500,
			extraOverhead: 32,
			wantErr:       true,
		},
	}

	// Execute every MTU validation scenario.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate the configured virtual MTU.
			err := ValidateInnerMTU(
				tt.virtualMTU,
				tt.physicalMTU,
				tt.extraOverhead,
			)

			// Verify the expected result.
			if (err != nil) != tt.wantErr {
				t.Fatalf(
					"ValidateInnerMTU() error = %v, wantErr = %v",
					err,
					tt.wantErr,
				)
			}
		})
	}
}
