# METADATA
# title: CycloneDX SBOM Contains Multiple CPEs
# description: >-
#   A CycloneDX SBOM that is version 1.6 and above has the ability to represent multiple CPEs using the metadata.component.cpe field for the main CPE, and the metadata.component.evidence.identity field for its aliases.
# custom:
#   short_name: CDX_MULTICPE
#   severity: tip
package prodsec.quality.cyclonedx.CDX_MULTICPE

import data.ec.lib
import data.ec.lib.util.is_cdx
import data.prodsec.util.is_cdx_equal_above_version
import data.ec.lib.util.reverse_index
import rego.v1

# Define the prerequisites to check for each policy (i.e. what SBOMs should these policies run on?)
prerequisite if {
	is_cdx
    is_cdx_equal_above_version("1.6")
    input.metadata.component.cpe
}

_policy_id := "CDX_MULTICPE"

# METADATA
# title: CycloneDX SBOM Uses Multi-CPE
# description: A given SBOM has a component within it that makes use of the evidence.identity field to define additional CPEs.
# custom:
#   short_name: cdx_contains_multicpe_example
#   failure_msg: TIP == This SBOM includes a main CPE and has been found to be CycloneDX v1.6 and above and supports representing multiple CPEs using the .cpe field as the main CPE and the .evidence.identity field to provide additional aliases of it. This method of CPE representation is also supported for Trustify SBOM ingestion.
#   severity: tip
deny contains result if {
	prerequisite
	example_snippet := { 
                "bom-ref": "example",
                "cpe": "main_cpe_here",
                "evidence": {
                "identity": [ 
                        {
                            "field": "cpe",
                            "concludedValue": "cpe_alias_here"
                        }
                    ]
                }
            }

    count(main_component_using_extra_cpes) == 0

	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{ "policy_id": _policy_id, "multi_cpe_example": example_snippet }
	)
}

main_component_using_extra_cpes contains result if {
    some i
    input.metadata.component.evidence.identity[i].field == "cpe"
    result := input.metadata.component.evidence.identity[i]
}