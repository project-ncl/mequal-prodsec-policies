package prodsec.util

import rego.v1

default is_cdx_v1_6_and_above := false
is_cdx_v1_6_and_above if {
	semver.compare(concat(".", [input.specVersion, "0"]), "1.6.0") <= 0
}