package dynamodb

import (
	"github.com/khulnasoft-lab/misscan/pkg/providers"
	"github.com/khulnasoft-lab/misscan/pkg/scan"
	"github.com/khulnasoft-lab/misscan/pkg/severity"
	"github.com/khulnasoft-lab/misscan/pkg/state"
	"github.com/khulnasoft-lab/tunnel-audit/pkg/rules"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0023",
		Provider:    providers.AWSProvider,
		Service:     "dynamodb",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "DAX Cluster should always encrypt data at rest",
		Impact:      "Data can be freely read if compromised",
		Resolution:  "Enable encryption at rest for DAX Cluster",
		Explanation: `Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection by helping secure your data from unauthorized access to the underlying storage.`,
		Links: []string{
			"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html",
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dax-cluster.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableAtRestEncryptionGoodExamples,
			BadExamples:         terraformEnableAtRestEncryptionBadExamples,
			Links:               terraformEnableAtRestEncryptionLinks,
			RemediationMarkdown: terraformEnableAtRestEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableAtRestEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableAtRestEncryptionBadExamples,
			Links:               cloudFormationEnableAtRestEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableAtRestEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.DynamoDB.DAXClusters {
			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if cluster.ServerSideEncryption.Enabled.IsFalse() {
				results.Add(
					"DAX encryption is not enabled.",
					cluster.ServerSideEncryption.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
