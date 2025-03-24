# METADATA
# title: CDX_MAINCOMPONENTDUP
# description: >-
#   ProdSec use-cases policy 1. Check if top component is duplicated into the components array in a CycloneDX SBOM.
package prodsec.quality.cyclonedx.CDX_MAINCOMPONENTDUP

import data.ec.lib
import data.ec.lib.util.is_cdx
import rego.v1

# Define the prerequisites to check for each policy (i.e. what SBOMs should these policies run on?)
prerequisite if {
	is_cdx
}

_policy_id := "CDX_MAINCOMPONENTDUP"

# METADATA
# title: Has top purl in components
# description: Check if the .metadata.component has been duplicated into the components[] array
# custom:
#   short_name: cdx_top_purl_in_components
#   failure_msg: CycloneDX SBOM top-purl does not have a duplicate in the components array for top-purl '%s'
deny contains result if {
	prerequisite
	top_purl := input.metadata.component.purl
	every component in input.components {
		component.purl != top_purl
	}
	result := object.union(
		lib.result_helper(rego.metadata.chain(), [top_purl]),
		{ "policy_id": _policy_id },
	)
}
