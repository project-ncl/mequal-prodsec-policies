# METADATA
# title: CycloneDX SBOM has a Main CPE
# description: >-
#   An SBOM can have a CPE field that ties it a product.
# custom:
#   short_name: CDX_CPE
#   severity: Normal
package prodsec.quality.cyclonedx.CDX_CPE

import data.ec.lib
import data.ec.lib.util.is_cdx
import rego.v1

# Define the prerequisites to check for each policy (i.e. what SBOMs should these policies run on?)
prerequisite if {
	is_cdx
}


_policy_id := "CDX_CPE"

# METADATA
# title: CycloneDX SBOM Has CPE
# description: The main component of a CycloneDX SBOM has a CPE.
# custom:
#   short_name: cdx_main_component_has_cpe
#   failure_msg: TIP == If this a product-level SBOM, it is advised to define a CPE in .metadata.component.cpe field to directly tie it to that product. If this is a component-level SBOM please disregard this tip.
guide contains result if {
	# violating condition of the policy
	prerequisite
	not input.metadata.component.cpe
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{ "policy_id": _policy_id },
	)
}
