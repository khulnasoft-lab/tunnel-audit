package sql

import (
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/providers/google/sql"
	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnablePgTempFileLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Instance temp files logging disabled for all files",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        misscanTypes.NewTestMetadata(),
						DatabaseVersion: misscanTypes.String("POSTGRES_12", misscanTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        misscanTypes.NewTestMetadata(),
								LogTempFileSize: misscanTypes.Int(-1, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance temp files logging disabled for files smaller than 100KB",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        misscanTypes.NewTestMetadata(),
						DatabaseVersion: misscanTypes.String("POSTGRES_12", misscanTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        misscanTypes.NewTestMetadata(),
								LogTempFileSize: misscanTypes.Int(100, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance temp files logging enabled for all files",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        misscanTypes.NewTestMetadata(),
						DatabaseVersion: misscanTypes.String("POSTGRES_12", misscanTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: misscanTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        misscanTypes.NewTestMetadata(),
								LogTempFileSize: misscanTypes.Int(0, misscanTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.SQL = test.input
			results := CheckEnablePgTempFileLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnablePgTempFileLogging.LongID() {
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
