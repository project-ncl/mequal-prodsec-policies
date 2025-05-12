package prodsec.policies.cyclonedx.CDX_VARIANTS_test

import data.ec.lib
import data.ec.lib.util.assert_passes_rules
import data.ec.lib.util.assert_violates_rules
import data.prodsec.policies.cyclonedx.CDX_VARIANTS
import rego.v1

_rule_cdx_variants_field_is_used := "prodsec.policies.cyclonedx.CDX_VARIANTS.cdx_variants_field_is_used"

# Prerequisites

# If not an SPDX, make sure no rules in this policy are evaluated (i.e. don't return violations)
test_prerequisite if {
	sbom := {"name": "John", "surname": "Smith"}
	results := CDX_VARIANTS.guide with input as sbom
	lib.assert_equal(count(results), 0)
}

# TODO
test_cdx_uses_variants if {
	sbom := {
		"bomFormat": "CycloneDX"
	}
	results := CDX_VARIANTS.guide with input as sbom
	assert_passes_rules(results, [_rule_cdx_variants_field_is_used])
}

# TODO
test_cdx_uses_variants_nested if {
	sbom := {
		"bomFormat": "CycloneDX"
	}
	results := CDX_VARIANTS.guide with input as sbom
	assert_passes_rules(results, [_rule_cdx_variants_field_is_used])
}

# TODO
test_cdx_does_not_variants if {
	sbom := {
		"bomFormat": "CycloneDX"
	}
	results := CDX_VARIANTS.guide with input as sbom
	assert_violates_rules(results, [_rule_cdx_variants_field_is_used])
}
