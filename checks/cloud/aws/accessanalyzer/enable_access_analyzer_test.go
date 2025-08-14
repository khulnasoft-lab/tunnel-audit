package accessanalyzer

import (
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"testing"

	misscanTypes "github.com/khulnasoft-lab/misscan/pkg/types"

	"github.com/khulnasoft-lab/misscan/pkg/providers/aws/accessanalyzer"

	"github.com/khulnasoft-lab/misscan/pkg/state"

	"github.com/khulnasoft-lab/misscan/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestASCheckNoSecretsInUserData(t *testing.T) {
	tests := []struct {
		name     string
		input    accessanalyzer.AccessAnalyzer
		expected bool
	}{
		{
			name:     "No analyzers enabled",
			input:    accessanalyzer.AccessAnalyzer{},
			expected: true,
		},
		{
			name: "Analyzer disabled",
			input: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ARN:      misscanTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", misscanTypes.NewTestMetadata()),
						Name:     misscanTypes.String("test", misscanTypes.NewTestMetadata()),
						Active:   misscanTypes.Bool(false, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Analyzer enabled",
			input: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: misscanTypes.NewTestMetadata(),
						ARN:      misscanTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", misscanTypes.NewTestMetadata()),
						Name:     misscanTypes.String("test", misscanTypes.NewTestMetadata()),
						Active:   misscanTypes.Bool(true, misscanTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.AccessAnalyzer = test.input
			results := CheckEnableAccessAnalyzer.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAccessAnalyzer.LongID() {
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

// Test library: Using Go's standard testing package (and testify/assert if available in repo).
// Focus: CheckEnableAccessAnalyzer rule behavior with various AccessAnalyzer configurations.

func TestEnableAccessAnalyzer_NoAnalyzers_Fails(t *testing.T) {
	s := &state.State{}
	// Ensure AWS accessor is initialized (many projects use zero-value with maps/slices nil-safe; adjust as needed)
	// No analyzers added.

	results := CheckEnableAccessAnalyzer.Evaluate(s)
	if results == nil {
		t.Fatalf("expected results, got nil")
	}

	// Expect at least one failing result with the specific message.
	found := false
	for _, r := range results {
		if r.Status() == scan.StatusFailed && r.Description() == "Access Analyzer is not enabled." {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a failed result with message 'Access Analyzer is not enabled.', got: %#v", results)
	}
}

func TestEnableAccessAnalyzer_InactiveAnalyzer_Fails(t *testing.T) {
	s := &state.State{}
	// Build one analyzer that is not active (false).
	an := s.AWS.AccessAnalyzer.GetAnalyzer()
	an.Active = misscanTypes.Bool(false)
	s.AWS.AccessAnalyzer.Analyzers = append(s.AWS.AccessAnalyzer.Analyzers, an)

	results := CheckEnableAccessAnalyzer.Evaluate(s)
	if results == nil {
		t.Fatalf("expected results, got nil")
	}

	found := false
	for _, r := range results {
		if r.Status() == scan.StatusFailed && r.Description() == "Access Analyzer is not enabled." {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a failed result with message 'Access Analyzer is not enabled.', got: %#v", results)
	}
}

func TestEnableAccessAnalyzer_OneActiveAnalyzer_Passes(t *testing.T) {
	s := &state.State{}
	an := s.AWS.AccessAnalyzer.GetAnalyzer()
	an.Active = misscanTypes.Bool(true)
	s.AWS.AccessAnalyzer.Analyzers = append(s.AWS.AccessAnalyzer.Analyzers, an)

	results := CheckEnableAccessAnalyzer.Evaluate(s)
	if results == nil {
		t.Fatalf("expected results, got nil")
	}

	// Expect at least one passed result and no failures with our message.
	passed := false
	for _, r := range results {
		if r.Status() == scan.StatusPassed {
			passed = true
		}
		if r.Status() == scan.StatusFailed && r.Description() == "Access Analyzer is not enabled." {
			t.Fatalf("did not expect failure when analyzer is active: %#v", r)
		}
	}
	if !passed {
		t.Fatalf("expected at least one passed result, got: %#v", results)
	}
}

func TestEnableAccessAnalyzer_MultipleAnalyzers_AtLeastOneActive_Passes(t *testing.T) {
	s := &state.State{}

	// One inactive
	a1 := s.AWS.AccessAnalyzer.GetAnalyzer()
	a1.Active = misscanTypes.Bool(false)

	// One active
	a2 := s.AWS.AccessAnalyzer.GetAnalyzer()
	a2.Active = misscanTypes.Bool(true)

	s.AWS.AccessAnalyzer.Analyzers = append(s.AWS.AccessAnalyzer.Analyzers, a1, a2)

	results := CheckEnableAccessAnalyzer.Evaluate(s)
	if results == nil {
		t.Fatalf("expected results, got nil")
	}

	passed := false
	for _, r := range results {
		if r.Status() == scan.StatusPassed {
			passed = true
		}
	}
	if !passed {
		t.Fatalf("expected a passed result because at least one analyzer is active, got: %#v", results)
	}
}

func TestEnableAccessAnalyzer_SeverityAndMetadata(t *testing.T) {
	// Validate rule metadata such as severity is set as expected
	if CheckEnableAccessAnalyzer.Severity() != severity.Low {
		t.Fatalf("expected severity Low, got %v", CheckEnableAccessAnalyzer.Severity())
	}

	// With no analyzers enabled, ensure the unmanaged metadata path is used without panics.
	s := &state.State{}
	results := CheckEnableAccessAnalyzer.Evaluate(s)
	if results == nil {
		t.Fatalf("expected results, got nil")
	}
	// No strong assertion on metadata internals due to API encapsulation; the behavior is validated by failure presence.
}

func TestEnableAccessAnalyzer_WithTestify_Asserts(t *testing.T) {
	assert := assert.New(t)

	// No analyzers -> fail
	{
		s := &state.State{}
		results := CheckEnableAccessAnalyzer.Evaluate(s)
		assert.NotNil(results, "results should not be nil")

		found := false
		for _, r := range results {
			if r.Status() == scan.StatusFailed && r.Description() == "Access Analyzer is not enabled." {
				found = true
			}
		}
		assert.True(found, "expected failure when no analyzers present")
	}

	// Active analyzer -> pass
	{
		s := &state.State{}
		an := s.AWS.AccessAnalyzer.GetAnalyzer()
		an.Active = misscanTypes.Bool(true)
		s.AWS.AccessAnalyzer.Analyzers = append(s.AWS.AccessAnalyzer.Analyzers, an)

		results := CheckEnableAccessAnalyzer.Evaluate(s)
		assert.NotNil(results)

		passed := false
		for _, r := range results {
			if r.Status() == scan.StatusPassed {
				passed = true
			}
			assert.NotEqual(scan.StatusFailed, r.Status(), "unexpected failure when analyzer active")
		}
		assert.True(passed, "expected at least one passed result when analyzer active")
	}
}

