package prodsec.util

import rego.v1

# Check if CycloneDX SBOM is equal or above a certain version
is_cdx_equal_above_version(version) if {
	semver.compare(concat(".", [input.specVersion, "0"]), concat(".", [version, "0"])) >= 0
}