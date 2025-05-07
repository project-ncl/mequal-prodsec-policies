# METADATA
# title: CycloneDX SBOM Uses Variants Field
# description: >-
#   Using the pedigree.variants field of a component inside of a CycloneDX SBOM, teams can represent the relationship of the image index container to their respective architectural variants in the CycloneDX SBOMs they generate. Supported by Trustify.
# custom:
#   short_name: CDX_VARIANTS
#   severity: tip
package prodsec.quality.cyclonedx.CDX_VARIANTS

import data.ec.lib
import data.ec.lib.util.is_cdx
import data.ec.lib.util.reverse_index
import rego.v1

# Define the prerequisites to check for each policy (i.e. what SBOMs should these policies run on?)
prerequisite if {
	is_cdx
}


_policy_id := "CDX_VARIANTS"

# METADATA
# title: Variants Field is Used in CycloneDX SBOM
# description: In a given CycloneDX SBOM, there are components where the pedigree.variants relationship is utilized.
# custom:
#   short_name: cdx_variants_field_is_used
#   failure_msg: TIP == In this SBOM, the pedigree.variants relationships have not been utilized. This field can represent the relationship of the image index container to their respective architectural variants in the CycloneDX SBOMs they generate. This field is supported for Trustify SBOM ingestion.
#   severity: tip
deny contains result if {
	prerequisite
	count(variant_components) == 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{ "policy_id": _policy_id },
	)
}

variant_components contains result if {
	prerequisite	
	some path, value
	walk(input.components, [path, value])
	is_number(reverse_index(path, 1))
	value["bom-ref"]
	path[count(path) - 2] == "variants"
	result := value["bom-ref"]
}