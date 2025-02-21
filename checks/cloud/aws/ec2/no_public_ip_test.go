package ec2

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIp(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "Launch configuration with public access",
			input: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata:          misscanTypes.NewTestMetadata(),
						AssociatePublicIP: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Launch configuration without public access",
			input: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata:          misscanTypes.NewTestMetadata(),
						AssociatePublicIP: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.EC2 = test.input
			results := CheckNoPublicIp.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIp.LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
