package prodsec.quality.cyclonedx.CDX_CPE_test

import data.ec.lib
import data.ec.lib.util.assert_passes_rules
import data.ec.lib.util.assert_violates_rules
import data.prodsec.quality.cyclonedx.CDX_CPE
import rego.v1

_rule_cdx_main_component_has_cpe := "prodsec.quality.cyclonedx.CDX_CPE.cdx_main_component_has_cpe"

# Prerequisites

# If not an SPDX, make sure no rules in this policy are evaluated (i.e. don't return violations)
test_prerequisite if {
	sbom := {"name": "John", "surname": "Smith"}
	results := CDX_CPE.guide with input as sbom
	lib.assert_equal(count(results), 0)
}

# TODO
test_cdx_uses_main_cpe if {
	sbom := {
		"bomFormat": "CycloneDX"
	}
	results := CDX_CPE.guide with input as sbom
	assert_passes_rules(results, [_rule_cdx_main_component_has_cpe])
}

# TODO
test_cdx_does_not_use_main_cpe if {
	sbom := {
		"bomFormat": "CycloneDX"
	}
	results := CDX_CPE.guide with input as sbom
	assert_violates_rules(results, [_rule_cdx_main_component_has_cpe])
}
