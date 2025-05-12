# METADATA
# title: CycloneDX SBOM Uses Provides Field
# description: >-
#   Using the dependencies section of a CycloneDX SBOM, the provides field can be used to specify what specification a certain component implements, or additionally can represent source-to-binary relationships.
# custom:
#   short_name: CDX_PROVIDES
#   severity: tip
package prodsec.policies.cyclonedx.CDX_PROVIDES

import data.ec.lib
import data.ec.lib.util.is_cdx
import rego.v1

# Define the prerequisites to check for each policy (i.e. what SBOMs should these policies run on?)
prerequisite if {
	is_cdx
}


_policy_id := "CDX_PROVIDES"

# METADATA
# title: Provides Field is Used in CycloneDX SBOM
# description: In a given CycloneDX SBOM, the provides relationship is utilized.
# custom:
#   short_name: cdx_provides_field_is_used
#   failure_msg: TIP == In this SBOM, the provides relationships have not been utilized. This field can be used to specify what specification a certain component implements. If SBOM is to be ingested by Trustify, the provides field is used to specify source-to-binary relationships.
#   severity: tip
deny contains result if {
	prerequisite
	count(components_using_provides) == 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{ "policy_id": _policy_id },
	)
}

components_using_provides contains result if {
	prerequisite
	some i
	input.dependencies[i].provides
	result := input.dependencies[i].ref
}
