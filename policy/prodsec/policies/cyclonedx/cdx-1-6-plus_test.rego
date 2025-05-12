package prodsec.policies.cyclonedx.CDX_1_6_PLUS_test

import data.ec.lib
import data.ec.lib.util.assert_passes_rules
import data.ec.lib.util.assert_violates_rules
import data.prodsec.policies.cyclonedx.CDX_1_6_PLUS
import rego.v1

_rule_cdx_sbom_is_cdx_1_6_and_above := "prodsec.policies.cyclonedx.CDX_1_6_PLUS.cdx_sbom_is_cdx_1_6_and_above"

# Prerequisites

# If not an SPDX, make sure no rules in this policy are evaluated (i.e. don't return violations)
test_prerequisite if {
	sbom := {"name": "John", "surname": "Smith"}
	results := CDX_1_6_PLUS.guide with input as sbom
	lib.assert_equal(count(results), 0)
}

test_cdx_equals_version_1_6 if {
	sbom := {
		"bomFormat": "CycloneDX",
		"specVersion": "1.6"
	}
	results := CDX_1_6_PLUS.guide with input as sbom
	assert_passes_rules(results, [_rule_cdx_sbom_is_cdx_1_6_and_above])
}

test_cdx_higher_than_version_1_6 if {
	sbom := {
		"bomFormat": "CycloneDX",
		"specVersion": "1.8"
	}
	results := CDX_1_6_PLUS.guide with input as sbom
	assert_passes_rules(results, [_rule_cdx_sbom_is_cdx_1_6_and_above])
}

test_cdx_lower_than_version_1_6 if {
	sbom := {
		"bomFormat": "CycloneDX",
		"specVersion": "1.4"
	}
	results := CDX_1_6_PLUS.guide with input as sbom
	assert_violates_rules(results, [_rule_cdx_sbom_is_cdx_1_6_and_above])
}
