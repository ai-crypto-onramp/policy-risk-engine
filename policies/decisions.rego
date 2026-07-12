package policy.decisions

default allow = false
default manual_review = false
default deny = false

# Allow when all signals are clean: amount within cap, KYT clean, fraud low,
# destination whitelisted, 2FA passed when required.
allow {
	input.amount_usd <= data.caps.tx.max_usd
	input.kyt_verdict == "clean"
	input.fraud_score < 0.5
	input.kyc_status == "verified"
	input.whitelisted == true
	not input.requires_2fa
}

allow {
	input.amount_usd <= data.caps.tx.max_usd
	input.kyt_verdict == "clean"
	input.fraud_score < 0.5
	input.kyc_status == "verified"
	input.whitelisted == true
	input.requires_2fa
	input.session_2fa_passed == true
}

# Manual review when fraud score is in the mid band.
manual_review {
	input.fraud_score >= 0.5
	input.fraud_score < 0.8
}

# Manual review when amount is near cap (>= 90% of daily cap).
manual_review {
	input.amount_usd >= data.caps.daily.max_usd * 0.9
	input.amount_usd <= data.caps.daily.max_usd
}

# Deny when fraud score is high.
deny {
	input.fraud_score >= 0.8
}

# Deny when KYT is sanctioned.
deny {
	input.kyt_verdict == "sanctioned"
}

# Deny when amount exceeds daily cap.
deny {
	input.amount_usd > data.caps.daily.max_usd
}

# Deny when destination is not whitelisted.
deny {
	input.whitelisted != true
}

# Deny when 2FA required but not passed.
deny {
	input.requires_2fa
	not input.session_2fa_passed
}

# Deny when KYC is not verified.
deny {
	input.kyc_status != "verified"
}

# Aggregate risk score: weighted sum of KYT, fraud, KYC signals.
risk_score = score {
	score := (kyt_weight(input.kyt_verdict) + input.fraud_score + kyc_weight(input.kyc_status)) / 3.0
}

kyt_weight("sanctioned") = 1.0
kyt_weight("high_risk") = 0.5
kyt_weight("clean") = 0.0
kyt_weight("unknown") = 0.2

kyc_weight("verified") = 0.0
kyc_weight("restricted") = 0.5
kyc_weight("expired") = 0.8
kyc_weight("unverified") = 1.0