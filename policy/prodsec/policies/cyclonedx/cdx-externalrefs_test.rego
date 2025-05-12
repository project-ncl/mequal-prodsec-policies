package prodsec.policies.cyclonedx.CDX_EXTERNALREFS_test

import data.ec.lib
import data.ec.lib.util.assert_passes_rules
import data.ec.lib.util.assert_violates_rules
import data.prodsec.policies.cyclonedx.CDX_EXTERNALREFS
import rego.v1

_rule_cdx_all_sbom_exrefs_valid_bomlink := "prodsec.policies.cyclonedx.CDX_EXTERNALREFS.cdx_all_sbom_exrefs_valid_bomlink"
_rule_cdx_all_sbom_exrefs_nonempty_bomuri := "prodsec.policies.cyclonedx.CDX_EXTERNALREFS.cdx_all_sbom_exrefs_nonempty_bomuri"
_rule_cdx_sbom_exrefs_used := "prodsec.policies.cyclonedx.CDX_EXTERNALREFS.cdx_sbom_exrefs_used"

# Prerequisites

# If not an SPDX, make sure no rules in this policy are evaluated (i.e. don't return violations)
test_prerequisite if {
	sbom := {"name": "John", "surname": "Smith"}
    deny_results := CDX_EXTERNALREFS.deny with input as sbom
    guide_results := CDX_EXTERNALREFS.guide with input as sbom
	lib.assert_equal(count(deny_results), 0)
    lib.assert_equal(count(guide_results), 0)
}

# TODO
test_cdx_placeholder_passes if {
	sbom := {
		"bomFormat": "CycloneDX"
	}
	results := CDX_EXTERNALREFS.deny with input as sbom
	assert_passes_rules(results, [])
}

# TODO
test_cdx_placeholder_violates if {
	sbom := {
		"bomFormat": "CycloneDX"
	}
	results := CDX_EXTERNALREFS.deny with input as sbom
	assert_violates_rules(results, [])
}
