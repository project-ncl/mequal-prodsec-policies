package prodsec.main

import data.prodsec.quality
import data.ec.lib.is_cdx
import rego.v1

prodsec_quality_guidance contains result if {
	result := quality[_][_].guide[_]
}

prodsec_quality_violations contains result if {
	result := quality[_][_].deny[_]
}

# cdx_variant_components_list := quality.cyclonedx.CDX_VARIANTS.variant_components
# cdx_ancestor_components_list := quality.cyclonedx.CDX_ANCESTORS.ancestor_components