# METADATA
# title: Specify the SBOM Type in CycloneDX
# description: >-
#   Teams who are generating an SBOM should define the type of SBOM it is. This can be done using the .metadata.lifecycles field. This policy ensures that different policies can be applied to different SBOM types. This also gives Mequal the option the opportunity to do SBOM evaluation in specific specialized contexts in the future.
# custom:
#   short_name: CDX_SBOMTYPE
#   severity: warning
package prodsec.quality.cyclonedx.CDX_SBOMTYPE

import data.ec.lib
import data.ec.lib.util.is_cdx
import rego.v1

# Define the prerequisites to check for each policy (i.e. what SBOMs should these policies run on?)
prerequisite if {
	is_cdx
}


_policy_id := "CDX_SBOMTYPE"

# METADATA
# title: CycloneDX Metadata.lifecycles Field Exists
# description: In a CycloneDX SBOM, the .metadata.lifecycles field exists.
# custom:
#   short_name: cdx_metadata_lifecycles_exists
#   failure_msg: The .metadata.lifecycles field has not been found in this SBOM. Defining an SBOM type helps Mequal evaluate SBOMs in different specialized contexts in the future.
#   severity: warning
deny contains result if {
	prerequisite
	not input.metadata.lifecycles
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{ "policy_id": _policy_id },
	)
}
