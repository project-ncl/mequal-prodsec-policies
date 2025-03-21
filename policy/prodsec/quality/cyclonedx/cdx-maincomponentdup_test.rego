package prodsec.quality.cyclonedx.CDX_MAINCOMPONENTDUP_test

import data.ec.lib
import data.ec.lib.util.assert_passes_rules
import data.ec.lib.util.assert_violates_rules
import data.prodsec.quality.cyclonedx.CDX_MAINCOMPONENTDUP
import rego.v1

_rule_cdx_top_purl_in_components := "prodsec.quality.cyclonedx.CDX_MAINCOMPONENTDUP.cdx_top_purl_in_components"

# Prerequisites

# If not an SPDX, make sure no rules in this policy are evaluated (i.e. don't return violations)
test_prerequisite if {
	sbom := {"name": "John", "surname": "Smith"}
	results := CDX_MAINCOMPONENTDUP.deny with input as sbom
	lib.assert_equal(count(results), 0)
}

# Top component duplicated

test_cdx_top_purl_in_components if {
	sbom := {
		"bomFormat": "CycloneDX",
		"metadata": {"component": {
			"name": "test",
			"purl": "test-purl",
		}},
		"components": [
			{"bom-ref": "test", "purl": "test-purl"},
			{"bom-ref": "test2", "purl": "test2"},
		],
	}
	results := CDX_MAINCOMPONENTDUP.deny with input as sbom
	assert_passes_rules(results, [_rule_cdx_top_purl_in_components])
}

test_cdx_top_purl_not_in_components if {
	sbom := {
		"bomFormat": "CycloneDX",
		"metadata": {"component": {
			"name": "test",
			"purl": "test-purl",
		}},
		"components": [
			{"bom-ref": "test", "purl": "test-purl-different"},
			{"bom-ref": "test2", "purl": "test2"},
		],
	}
	results := CDX_MAINCOMPONENTDUP.deny with input as sbom
	assert_violates_rules(results, [_rule_cdx_top_purl_in_components])
}
