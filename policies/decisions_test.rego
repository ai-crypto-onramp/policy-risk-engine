package policy.decisions

import rego.v1

test_allow_clean_whitelisted_2fa_ok if {
	allow with input as {
		"amount_usd": 100.0,
		"kyt_verdict": "clean",
		"fraud_score": 0.1,
		"kyc_status": "verified",
		"dest_address": "0xabc",
		"whitelisted": true,
		"requires_2fa": false,
	}
}

test_allow_clean_whitelisted_2fa_required_and_passed if {
	allow with input as {
		"amount_usd": 1500.0,
		"kyt_verdict": "clean",
		"fraud_score": 0.1,
		"kyc_status": "verified",
		"dest_address": "0xabc",
		"whitelisted": true,
		"requires_2fa": true,
		"session_2fa_passed": true,
	}
}

test_deny_not_whitelisted if {
	deny with input as {
		"amount_usd": 100.0,
		"kyt_verdict": "clean",
		"fraud_score": 0.1,
		"kyc_status": "verified",
		"dest_address": "0xabc",
		"whitelisted": false,
		"requires_2fa": false,
	}
}

test_deny_fraud_high if {
	deny with input as {
		"amount_usd": 100.0,
		"kyt_verdict": "clean",
		"fraud_score": 0.9,
		"kyc_status": "verified",
		"dest_address": "0xabc",
		"whitelisted": true,
		"requires_2fa": false,
	}
}

test_deny_kyt_sanctioned if {
	deny with input as {
		"amount_usd": 100.0,
		"kyt_verdict": "sanctioned",
		"fraud_score": 0.1,
		"kyc_status": "verified",
		"dest_address": "0xabc",
		"whitelisted": true,
		"requires_2fa": false,
	}
}

test_deny_2fa_required_not_passed if {
	deny with input as {
		"amount_usd": 1500.0,
		"kyt_verdict": "clean",
		"fraud_score": 0.1,
		"kyc_status": "verified",
		"dest_address": "0xabc",
		"whitelisted": true,
		"requires_2fa": true,
		"session_2fa_passed": false,
	}
}

test_deny_kyc_not_verified if {
	deny with input as {
		"amount_usd": 100.0,
		"kyt_verdict": "clean",
		"fraud_score": 0.1,
		"kyc_status": "restricted",
		"dest_address": "0xabc",
		"whitelisted": true,
		"requires_2fa": false,
	}
}

test_manual_review_fraud_mid if {
	manual_review with input as {
		"amount_usd": 100.0,
		"kyt_verdict": "clean",
		"fraud_score": 0.6,
		"kyc_status": "verified",
		"dest_address": "0xabc",
		"whitelisted": true,
		"requires_2fa": false,
	}
}

test_risk_score_clean if {
	score := risk_score with input as {
		"kyt_verdict": "clean",
		"fraud_score": 0.0,
		"kyc_status": "verified",
	}
	score == 0.0
}

test_risk_score_high_risk_kyt if {
	score := risk_score with input as {
		"kyt_verdict": "high_risk",
		"fraud_score": 0.3,
		"kyc_status": "verified",
	}
	# (0.5 + 0.3 + 0.0) / 3.0 = 0.266...
	score > 0.26
	score < 0.27
}