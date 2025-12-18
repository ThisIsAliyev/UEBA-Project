"""
Score Integration Module.

Combines scores from multiple sources into a final risk score:
- Rule-based scoring (fast, deterministic)
- Baseline deviation (behavioral anomaly)
- Whitelist/blacklist modifiers
- AI Server analysis (slow, uncertain cases)
- n8n enrichment (VirusTotal, AbuseIPDB)

The combination follows security best practices:
- AI can escalate but has limited ability to downgrade
- Blacklist matches are strong signals
- Whitelist matches reduce but don't eliminate risk
"""

import logging
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass

from .models import EnrichmentResponse, RiskLabel

logger = logging.getLogger(__name__)


@dataclass
class ScoreComponents:
    """All score components for an event."""
    rule_score: float = 0.0
    feature_score: float = 0.0
    baseline_deviation: float = 0.0
    list_modifier: int = 0
    ai_score: Optional[float] = None
    ai_label: Optional[RiskLabel] = None
    ai_confidence: float = 0.0
    vt_score: Optional[float] = None
    vt_label: Optional[RiskLabel] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_score": self.rule_score,
            "feature_score": self.feature_score,
            "baseline_deviation": self.baseline_deviation,
            "list_modifier": self.list_modifier,
            "ai_score": self.ai_score,
            "ai_label": self.ai_label.value if self.ai_label else None,
            "ai_confidence": self.ai_confidence,
            "vt_score": self.vt_score,
            "vt_label": self.vt_label.value if self.vt_label else None,
        }


# Score weights for combination formula
WEIGHTS = {
    "rule": 0.35,       # Static rule matches
    "feature": 0.15,    # Feature-based scoring
    "baseline": 0.20,   # Baseline deviation
    "vt": 0.30,         # VirusTotal/threat intel (when available)
}

# Risk level thresholds
RISK_LEVELS = {
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 20,
    "info": 0,
}


def calculate_preliminary_score(
    rule_score: float,
    feature_score: float,
    baseline_deviation: float,
    list_modifier: int
) -> float:
    """
    Calculate preliminary score before AI/VT enrichment.
    
    Formula:
        base = (rule * 0.35) + (feature * 0.15) + (baseline * 0.20)
        preliminary = base + list_modifier
        
    List modifier:
        - Whitelist: -30 to -50 (reduces score)
        - Blacklist: +30 to +80 (increases score)
    
    Args:
        rule_score: Score from rule-based engine (0-100)
        feature_score: Score from feature extraction (0-100)
        baseline_deviation: Score from baseline manager (0-100)
        list_modifier: Modifier from whitelist/blacklist (-50 to +80)
        
    Returns:
        Preliminary score (0-100)
    """
    # Weighted base score (without VT, which comes later)
    # Redistribute VT weight to other components
    adjusted_weights = {
        "rule": 0.50,
        "feature": 0.20,
        "baseline": 0.30,
    }
    
    base_score = (
        adjusted_weights["rule"] * rule_score +
        adjusted_weights["feature"] * feature_score +
        adjusted_weights["baseline"] * baseline_deviation
    )
    
    # Apply list modifier
    preliminary = base_score + list_modifier
    
    # Clamp to 0-100
    return max(0.0, min(100.0, preliminary))


def integrate_vt_score(
    current_score: float,
    vt_response: EnrichmentResponse
) -> Tuple[float, str]:
    """
    Integrate VirusTotal/n8n enrichment into score.
    
    VT is authoritative for known-bad:
    - If VT says MALICIOUS with high detections, trust it
    - If VT says BENIGN, reduce score but don't eliminate risk
    
    Args:
        current_score: Current preliminary score
        vt_response: Response from n8n/VT enrichment
        
    Returns:
        Tuple of (updated_score, reason)
    """
    if vt_response.error:
        # VT unavailable, use current score
        return current_score, "VT unavailable"
    
    vt_score = float(vt_response.score)
    vt_label = vt_response.label
    
    if vt_label == RiskLabel.MALICIOUS:
        # VT says malicious - this is a strong signal
        # Take the higher of current score or VT score
        if vt_score >= 70:
            new_score = max(current_score, vt_score * 0.95)
            return new_score, f"VT malicious ({vt_score})"
        else:
            # Lower VT score but still malicious
            new_score = max(current_score, (current_score + vt_score) / 2)
            return new_score, f"VT suspicious-malicious ({vt_score})"
    
    elif vt_label == RiskLabel.BENIGN:
        # VT says benign - reduce score but maintain floor
        if current_score > 50:
            # Don't fully trust VT if rules flagged it
            new_score = current_score * 0.8
            return new_score, f"VT benign, rules suspicious"
        else:
            new_score = min(current_score, vt_score)
            return new_score, f"VT benign ({vt_score})"
    
    else:  # SUSPICIOUS
        # VT uncertain - blend scores
        new_score = (current_score * 0.6) + (vt_score * 0.4)
        return new_score, f"VT suspicious ({vt_score})"


def integrate_ai_score(
    current_score: float,
    ai_response: EnrichmentResponse
) -> Tuple[float, str]:
    """
    Integrate AI Server analysis into final score.
    
    AI integration rules:
    1. AI MALICIOUS can escalate score significantly
    2. AI SUSPICIOUS confirms uncertainty
    3. AI BENIGN can reduce score but not below floor if rules flagged it
    4. AI confidence affects weight of adjustment
    
    Args:
        current_score: Current score (after VT if available)
        ai_response: Response from AI Server
        
    Returns:
        Tuple of (final_score, reason)
    """
    if ai_response.error:
        # AI unavailable, use current score
        return current_score, "AI unavailable"
    
    ai_score = float(ai_response.score)
    ai_label = ai_response.label
    ai_confidence = ai_response.confidence
    
    # Weight AI contribution by confidence
    # Low confidence = less influence
    ai_weight = 0.4 * ai_confidence
    rule_weight = 1.0 - ai_weight
    
    if ai_label == RiskLabel.MALICIOUS:
        # AI says malicious - can escalate significantly
        if ai_confidence >= 0.7:
            # High confidence malicious - strong escalation
            new_score = max(current_score, ai_score)
            # Ensure minimum score for malicious verdict
            new_score = max(new_score, 70)
            return new_score, f"AI malicious (conf={ai_confidence:.2f})"
        else:
            # Lower confidence - moderate escalation
            new_score = max(current_score, (current_score + ai_score) / 2)
            return new_score, f"AI malicious-uncertain (conf={ai_confidence:.2f})"
    
    elif ai_label == RiskLabel.BENIGN:
        # AI says benign - can reduce but with limits
        if current_score >= 60:
            # Rules/VT flagged it high - AI can reduce but maintain floor
            floor = 40 if current_score >= 70 else 30
            new_score = max(floor, current_score * (1 - ai_weight * 0.5))
            return new_score, f"AI benign, rules high (floor={floor})"
        else:
            # Lower current score - AI can reduce more
            new_score = (rule_weight * current_score) + (ai_weight * ai_score)
            return new_score, f"AI benign (conf={ai_confidence:.2f})"
    
    else:  # SUSPICIOUS
        # AI confirms uncertainty - blend scores
        new_score = (rule_weight * current_score) + (ai_weight * ai_score)
        return new_score, f"AI suspicious (conf={ai_confidence:.2f})"


def calculate_final_score(components: ScoreComponents) -> Tuple[float, str, str]:
    """
    Calculate final risk score from all components.
    
    Pipeline:
    1. Calculate preliminary score (rule + feature + baseline + list)
    2. Integrate VT score if available
    3. Integrate AI score if available
    4. Determine risk level
    
    Args:
        components: ScoreComponents with all available scores
        
    Returns:
        Tuple of (final_score, risk_level, explanation)
    """
    explanations = []
    
    # Step 1: Preliminary score
    score = calculate_preliminary_score(
        components.rule_score,
        components.feature_score,
        components.baseline_deviation,
        components.list_modifier
    )
    explanations.append(f"preliminary={score:.1f}")
    
    # Step 2: Integrate VT if available
    if components.vt_score is not None and components.vt_label is not None:
        vt_response = EnrichmentResponse(
            request_id="",
            label=components.vt_label,
            score=int(components.vt_score),
            confidence=0.8,
            reason="",
            comment="",
            source="vt"
        )
        score, vt_reason = integrate_vt_score(score, vt_response)
        explanations.append(vt_reason)
    
    # Step 3: Integrate AI if available
    if components.ai_score is not None and components.ai_label is not None:
        ai_response = EnrichmentResponse(
            request_id="",
            label=components.ai_label,
            score=int(components.ai_score),
            confidence=components.ai_confidence,
            reason="",
            comment="",
            source="ai"
        )
        score, ai_reason = integrate_ai_score(score, ai_response)
        explanations.append(ai_reason)
    
    # Clamp final score
    final_score = max(0.0, min(100.0, score))
    
    # Determine risk level
    risk_level = determine_risk_level(final_score)
    
    explanation = " → ".join(explanations)
    
    return final_score, risk_level, explanation


def determine_risk_level(score: float) -> str:
    """
    Determine risk level from score.
    
    Levels:
    - critical: 80-100
    - high: 60-79
    - medium: 40-59
    - low: 20-39
    - info: 0-19
    """
    if score >= RISK_LEVELS["critical"]:
        return "critical"
    elif score >= RISK_LEVELS["high"]:
        return "high"
    elif score >= RISK_LEVELS["medium"]:
        return "medium"
    elif score >= RISK_LEVELS["low"]:
        return "low"
    else:
        return "info"


def should_trigger_ai(
    preliminary_score: float,
    event_id: Optional[int],
    baseline_deviation: float,
    list_match_type: str
) -> bool:
    """
    Determine if event should be sent to AI for analysis.
    
    AI is expensive (slow), so we're selective:
    1. Uncertain scores (40-70 range) where rules aren't definitive
    2. High baseline deviation with medium score
    3. High-value Sysmon event types with score >= 35
    4. Skip if clearly benign or clearly malicious
    5. Skip if blacklist already matched (confident)
    
    Args:
        preliminary_score: Score after rule + baseline + list
        event_id: Sysmon/Windows event ID
        baseline_deviation: Baseline deviation score
        list_match_type: "whitelist", "blacklist", or "none"
        
    Returns:
        True if AI analysis should be triggered
    """
    # Skip if blacklist matched - already confident
    if list_match_type == "blacklist":
        return False
    
    # Skip if clearly benign
    if preliminary_score < 30 and baseline_deviation < 30:
        return False
    
    # Skip if already very high (confident malicious)
    if preliminary_score >= 85:
        return False
    
    # Trigger for uncertain range
    if 40 <= preliminary_score <= 70:
        return True
    
    # Trigger for high baseline deviation
    if baseline_deviation >= 50 and preliminary_score >= 30:
        return True
    
    # High-value Sysmon event types
    high_value_events = {
        1,   # Process Create
        3,   # Network Connect
        7,   # Image Load
        8,   # CreateRemoteThread
        10,  # ProcessAccess
        11,  # FileCreate
        12,  # Registry Event (Object create/delete)
        13,  # Registry Event (Value Set)
        22,  # DNS Query
    }
    
    if event_id in high_value_events and preliminary_score >= 35:
        return True
    
    return False


def should_trigger_n8n(
    preliminary_score: float,
    has_hash: bool,
    has_ip: bool,
    has_url: bool,
    has_domain: bool
) -> bool:
    """
    Determine if event should be sent to n8n for IOC enrichment.
    
    Only call n8n if:
    1. We have an IOC to look up (hash, IP, URL, or domain)
    2. Score is above threshold (don't waste quota on benign)
    
    Args:
        preliminary_score: Score after rule + baseline + list
        has_hash: Event has file hash
        has_ip: Event has destination IP
        has_url: Event has URL
        has_domain: Event has domain
        
    Returns:
        True if n8n enrichment should be triggered
    """
    # Must have at least one IOC
    has_ioc = has_hash or has_ip or has_url or has_domain
    if not has_ioc:
        return False
    
    # Only enrich if score warrants it
    return preliminary_score >= 30
