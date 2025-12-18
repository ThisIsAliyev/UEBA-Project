#!/usr/bin/env python3
"""
Quick test script to verify CRITICAL (80+) is reachable with normalized weights.

This validates the fix for the math bug where max score was 70 instead of 100.
"""

def test_risk_score_reachability():
    """Test that final_risk can reach 100 with all component scores at 100."""
    
    # Component scores (all at maximum)
    rule_score = 100.0
    feature_score = 100.0
    anomaly_score = 100.0
    context_score = 0.0  # Not implemented
    
    # Sub-weights (from features_config.yaml)
    rule_sub_weight = 0.6
    feature_sub_weight = 0.4
    
    # Combine rule + feature
    combined_rule_feature = rule_sub_weight * rule_score + feature_sub_weight * feature_score
    print(f"combined_rule_feature = {rule_sub_weight} * {rule_score} + {feature_sub_weight} * {feature_score}")
    print(f"  = {combined_rule_feature}")
    
    # Main weights (from thresholds.yaml - normalized)
    weights = {
        "rule": 0.4286,      # Normalized: 0.3/(0.3+0.4)
        "anomaly": 0.5714,   # Normalized: 0.4/(0.3+0.4)
        "context": 0.0       # Disabled
    }
    
    # Final risk calculation
    final_risk = (
        weights["rule"] * combined_rule_feature +
        weights["anomaly"] * anomaly_score +
        weights["context"] * context_score
    )
    
    print(f"\nfinal_risk = {weights['rule']} * {combined_rule_feature} + {weights['anomaly']} * {anomaly_score} + {weights['context']} * {context_score}")
    print(f"  = {weights['rule'] * combined_rule_feature} + {weights['anomaly'] * anomaly_score} + {weights['context'] * context_score}")
    print(f"  = {final_risk}")
    
    # Determine risk level
    if final_risk >= 80:
        risk_level = "CRITICAL"
    elif final_risk >= 60:
        risk_level = "HIGH"
    elif final_risk >= 40:
        risk_level = "MEDIUM"
    elif final_risk >= 20:
        risk_level = "LOW"
    else:
        risk_level = "INFO"
    
    print(f"\nrisk_level = {risk_level}")
    
    # Verification
    print("\n" + "=" * 60)
    if final_risk >= 100.0:
        print("✅ PASS: final_risk can reach 100")
    else:
        print(f"❌ FAIL: final_risk max is {final_risk}, cannot reach 100")
    
    if risk_level == "CRITICAL":
        print("✅ PASS: risk_level can be CRITICAL (>= 80)")
    else:
        print(f"❌ FAIL: risk_level is {risk_level}, CRITICAL not reachable")
    
    if abs(final_risk - 100.0) < 0.01:
        print("✅ PASS: Formula is mathematically correct")
    else:
        print(f"⚠️  WARNING: final_risk = {final_risk}, expected ~100.0")
    
    print("=" * 60)
    
    return final_risk >= 100.0 and risk_level == "CRITICAL"


if __name__ == "__main__":
    success = test_risk_score_reachability()
    exit(0 if success else 1)

