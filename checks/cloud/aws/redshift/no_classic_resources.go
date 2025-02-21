package redshift

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	"github.com/khulnasoft-lab/tunnel-audit/pkg/rules"
)

var CheckNoClassicResources = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0085",
		Provider:   providers.AWSProvider,
		Service:    "redshift",
		ShortCode:  "no-classic-resources",
		Summary:    "AWS Classic resource usage.",
		Impact:     "Classic resources are running in a shared environment with other customers",
		Resolution: "Switch to VPC resources",
		Explanation: `AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
resources in a VPC instead.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html",
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoClassicResourcesGoodExamples,
			BadExamples:         cloudFormationNoClassicResourcesBadExamples,
			Links:               cloudFormationNoClassicResourcesLinks,
			RemediationMarkdown: cloudFormationNoClassicResourcesRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.AWS.Redshift.SecurityGroups {
			results.Add(
				"Classic resources should not be used.",
				&group,
			)
		}
		return
	},
)
