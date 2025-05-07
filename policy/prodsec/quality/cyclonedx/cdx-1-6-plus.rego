# METADATA
# title: Teams should use CycloneDX 1.6 and above to use key features
# description: >-
#   Teams who are generating am SBOM will benefit from using CycloneDX version 1.6 and above in order to access key features that make it much easier to represent certain information, such as multiple CPEs and PURLs. This policy gives informational feedback on the advantages of using version CycloneDX 1.6 and above.
# custom:
#   short_name: CDX_1_6_PLUS
#   severity: tip
package prodsec.quality.cyclonedx.CDX_1_6_PLUS

import data.ec.lib
import data.ec.lib.util.is_cdx
import data.prodsec.util.is_cdx_equal_above_version
import rego.v1

# Define the prerequisites to check for each policy (i.e. what SBOMs should these policies run on?)
prerequisite if {
	is_cdx
}


_policy_id := "CDX_1_6_PLUS"

# METADATA
# title: SBOM is CycloneDX 1.6 and Above
# description: SBOM is CycloneDX 1.6 and above in order to ensure support of potentially important features.
# custom:
#   short_name: cdx_sbom_is_cdx_1_6_and_above
#   failure_msg: The CycloneDX version of this SBOM may not support important features that may be required for complete and accurate manifesting. In order to properly represent multiple PURLs and multiple CPEs of an SBOM, CycloneDX version 1.6 and above is needed.
#   severity: tip
deny contains result if {
	prerequisite
	# violating condition (SBOM is NOT 1.6 and above)
	not is_cdx_equal_above_version("1.6")
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{ "policy_id": _policy_id },
	)
}
