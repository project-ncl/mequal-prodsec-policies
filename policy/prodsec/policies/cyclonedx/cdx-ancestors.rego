# METADATA
# title: CycloneDX SBOM Uses Ancestors Field
# description: >-
#   Using the pedigree.ancestors field of a component inside of a CycloneDX SBOM, teams can denote the upstream of a component in the SBOMs they generate. Supported by Trustify.
# custom:
#   short_name: CDX_ANCESTORS
#   severity: tip
package prodsec.policies.cyclonedx.CDX_ANCESTORS

import data.ec.lib
import data.ec.lib.util.is_cdx
import data.ec.lib.util.reverse_index
import rego.v1

# Define the prerequisites to check for each policy (i.e. what SBOMs should these policies run on?)
prerequisite if {
	is_cdx
}

_policy_id := "CDX_ANCESTORS"

# METADATA
# title: Ancestors Field is Used in CycloneDX SBOM
# description: In a given CycloneDX SBOM, there are components where the pedigree.ancestors relationship is utilized.
# custom:
#   short_name: cdx_ancestors_field_is_used
#   failure_msg: TIP == In this SBOM, the pedigree.ancestors relationships have not been utilized. This field can denote the upstream of a component. This field is supported for Trustify SBOM ingestion.
#   severity: tip
deny contains result if {
	prerequisite
	# violating condition of the policy (no ancestor components found in the sbom)
	count(ancestor_components) == 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{ "policy_id": _policy_id },
	)
}

ancestor_components contains result if {
	prerequisite	
	some path, value
	walk(input.components, [path, value])
	is_number(reverse_index(path, 1))
	value["bom-ref"]
	path[count(path) - 2] == "ancestors"
	result := value["bom-ref"]
}
