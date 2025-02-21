package ec2

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/ec2"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireVPCFlowLogs(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "VPC without flow logs enabled",
			input: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        misscanTypes.NewTestMetadata(),
						ID:              misscanTypes.String("vpc-12345678", misscanTypes.NewTestMetadata()),
						FlowLogsEnabled: misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "VPC with flow logs enabled",
			input: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        misscanTypes.NewTestMetadata(),
						ID:              misscanTypes.String("vpc-12345678", misscanTypes.NewTestMetadata()),
						FlowLogsEnabled: misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
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
			results := CheckRequireVPCFlowLogs.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireVPCFlowLogs.LongID() {
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
