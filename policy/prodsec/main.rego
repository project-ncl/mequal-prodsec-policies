package prodsec.main

import data.prodsec.policies
import data.ec.lib.is_cdx
import data.prodsec.summary
import rego.v1

prodsec_quality_violations contains result if {
	eval := policies[_][_].deny[_]
	result := eval_object(
		eval.policy_id,
		eval.code,
		eval.msg
	)
}

eval_object(policy_id, rule_id, message) := x if {
	x:= {
		"policy_id": policy_id,
		"rule_id": rule_id,
		"message": message,
	}
}