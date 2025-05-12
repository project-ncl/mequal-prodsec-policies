# METADATA
# title: CycloneDX SBOM Contains Multiple PURLs
# description: >-
#   A CycloneDX SBOM that is version 1.6 and above has the ability to represent multiple PURLs using .purl field for the main PURL, and the .evidence.identity field for its aliases.
# custom:
#   short_name: CDX_MULTIPURL
#   severity: tip
package prodsec.policies.cyclonedx.CDX_MULTIPURL

import data.ec.lib
import data.ec.lib.util.is_cdx
import data.prodsec.util.is_cdx_equal_above_version
import data.ec.lib.util.reverse_index
import rego.v1

# Define the prerequisites to check for each policy (i.e. what SBOMs should these policies run on?)
prerequisite if {
	is_cdx
    is_cdx_equal_above_version("1.6")
}


_policy_id := "CDX_MULTIPURL"

# METADATA
# title: CycloneDX SBOM Uses Multi-PURL
# description: A given SBOM has a component within it that makes use of the evidence.identity field to define additional PURLs.
# custom:
#   short_name: cdx_contains_multipurl_example
#   failure_msg: TIP == This SBOM has been found to be CycloneDX v1.6 and above, and supports representing multiple PURLs using the .purl field as the main PURL and the .evidence.identity field to provide additional aliases of it. This method of PURL representation is also supported for Trustify SBOM ingestion.
#   severity: tip
deny contains result if {
	prerequisite
	example_snippet := { 
                "bom-ref": "example",
                "purl": "main_purl_here",
                "evidence": {
                "identity": [ 
                        {
                            "field": "purl",
                            "concludedValue": "purl_alias_here"
                        }
                    ]
                }
            }

    count(components_using_extra_purls) == 0
    
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{ "policy_id": _policy_id, "multipurl_example": example_snippet }
	    )
}

components_using_extra_purls contains result if {
    prerequisite	
	some path, value
	walk(input.components, [path, value])
	is_number(reverse_index(path, 1))
	value["bom-ref"]
    some i
    value.evidence.identity[i].field == "purl"
    result := value
}