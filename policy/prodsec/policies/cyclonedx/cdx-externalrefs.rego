# METADATA
# title: CycloneDX SBOM Makes Valid External References to other SBOMs
# description: >-
#   When teams produce an SBOM for their product, they will most likely NOT be putting all transitive layers into a single SBOM. This policy would ensure that the references to external SBOMs made are defined using the correct fields and are syntactically correct. Making sure that these references are correctly written is crucial for the relationships to accurately make it into TPA.
# custom:
#   short_name: CDX_EXTERNALREFS
#   severity: error
package prodsec.policies.cyclonedx.CDX_EXTERNALREFS

import data.ec.lib
import data.ec.lib.util.is_cdx
import data.prodsec.util.is_cdx_equal_above_version
import data.ec.lib.util.reverse_index
import rego.v1

# Define the prerequisites to check for each policy (i.e. what SBOMs should these policies run on?)
prerequisite if {
	is_cdx
}

_policy_id := "CDX_EXTERNALREFS"

# METADATA
# title: All Bomlink SBOM References are Valid
# description: Given an SBOM, ensure that all Bomlink external references to other SBOMs are valid in format.
# custom:
#   short_name: cdx_all_sbom_exrefs_valid_bomlink
#   failure_msg: An invalid Bomlink external reference to an SBOM has been found in component purls %s
#   severity: error
deny contains result if {
	prerequisite
	is_cdx_equal_above_version("1.5") # additional prerequisite for this rule since bomlink support starts from v1.5
	# violating condition (Bomlink badly defined)
	count(component_bomrefs_with_invalid_bomlink_references) > 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), [component_bomrefs_with_invalid_bomlink_references]),
		{ "policy_id": _policy_id },
	)
}

component_bomrefs_with_invalid_bomlink_references contains result if {
	some i,j
	external_ref := components_with_bom_references[i]["externalReferences"][j]
	# since bom-link and bom-uri use the same space to define relation, avoid http linkages for checking bom-link
	not startswith(external_ref["url"], "http")
	not regex.match(`^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*$`, external_ref["url"])
	result := components_with_external_references[i]["bom-ref"]
}


# METADATA
# title: All Bom uri SBOM References Have Non-empty URL Fields
# description: Given an SBOM, ensure that all SBOM external references to other SBOMs done using the bom uri field are non-empty in format.
# custom:
#   short_name: cdx_all_sbom_exrefs_nonempty_bomuri
#   failure_msg: An empty bom uri external reference to an SBOM has been found in component purls %s
#   severity: error
deny contains result if {
	prerequisite
	count(component_bomrefs_with_empty_bom_uri_references) > 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), [component_bomrefs_with_empty_bom_uri_references]),
		{ "policy_id": _policy_id },
	)
}

component_bomrefs_with_empty_bom_uri_references contains result if {
	some i,j
	external_ref := components_with_bom_references[i]["externalReferences"][j]
	external_ref["url"] == ""
	result := components_with_external_references[i]["bom-ref"]
}

# METADATA
# title: External SBOM References Used
# description: Given an SBOM, there have been external references identified.
# custom:
#   short_name: cdx_sbom_exrefs_used
#   failure_msg: TIP == No external SBOM references have been found in this SBOM. Referencing other SBOMs are possible with the bom uri field, or using the Bomlink method if SBOM is CycloneDX 1.5 or higher.
#   severity: tip
deny contains result if {
	prerequisite
	count(components_with_bom_references) == 0
	result := object.union(
		lib.result_helper(rego.metadata.chain(), []),
		{ "policy_id": _policy_id },
	)
}

components_with_bom_references contains result if {
	some i,j
	external_ref := components_with_external_references[i]["externalReferences"][j]
	external_ref["type"] == "bom"
	result := components_with_external_references[i]
}

components_with_external_references contains result if {
	prerequisite
	some path, value
	walk(input.components, [path, value])
	is_number(reverse_index(path, 1))
	value["bom-ref"]
	value["externalReferences"]
	result := value
}