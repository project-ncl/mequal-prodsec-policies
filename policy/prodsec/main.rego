package prodsec.main

import data.prodsec.quality
import rego.v1

prodsec_quality_guidance contains result if {
	result := quality[_][_].deny[_]
}
