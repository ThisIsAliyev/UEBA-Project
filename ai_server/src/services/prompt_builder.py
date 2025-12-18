"""
Prompt construction for security analysis.

Builds structured prompts that guide the LLM to produce consistent,
machine-parseable responses in the canonical JSON format.
"""

import json
from typing import Dict, Any
from ..models.schemas import AnalyzeRequest


# System prompt that enforces structured output
SYSTEM_PROMPT = """You are a cybersecurity analyst AI specializing in endpoint detection and response (EDR).
Your task is to analyze Windows security events and determine if they indicate malicious activity.

CRITICAL: You MUST respond ONLY with a valid JSON object in this EXACT format:
{
  "label": "MALICIOUS" or "SUSPICIOUS" or "BENIGN",
  "score": <integer 0-100>,
  "confidence": <float 0.0-1.0>,
  "reason": "<short 1-sentence explanation for logs>",
  "comment": "<detailed 2-3 sentence explanation for analysts>"
}

Scoring guidelines:
- 0-19: Clearly benign, normal system activity
- 20-39: Minor anomaly, likely benign but notable
- 40-59: Suspicious, warrants investigation
- 60-79: Likely malicious, high priority investigation
- 80-100: Confirmed malicious indicators, immediate action needed

Focus on these attack indicators:
1. Living-off-the-land binaries (LOLBins): PowerShell, cmd, wscript, cscript, mshta, regsvr32
2. Suspicious process chains: Office apps spawning shells, browsers spawning cmd
3. Encoded/obfuscated commands: Base64, -enc, -encodedcommand, -e
4. Suspicious paths: Temp, Downloads, AppData, ProgramData, Recycle Bin
5. Credential access: lsass.exe access, SAM/SECURITY hive access
6. Defense evasion: Disabling security tools, clearing logs
7. Persistence: Registry Run keys, scheduled tasks, services
8. Lateral movement: Remote process creation, PsExec patterns

Consider the baseline deviation and threat intel if provided.
If the rule_score is already high (>70), focus on confirming or refuting the threat.
If the rule_score is in the uncertain range (40-70), provide decisive analysis.

DO NOT include any text outside the JSON object. No explanations, no markdown, just JSON."""


def build_analysis_prompt(request: AnalyzeRequest) -> str:
    """
    Build the analysis prompt from request data.
    
    Args:
        request: AnalyzeRequest containing events and context
        
    Returns:
        Formatted prompt string for Ollama
    """
    parts = [SYSTEM_PROMPT, "\n\n--- SECURITY EVENTS TO ANALYZE ---\n"]
    
    # Add events (limit to 5 most recent for context window)
    for i, event in enumerate(request.events[:5], 1):
        parts.append(f"\nEvent {i}:")
        
        # Core event fields
        if event.get("process_name"):
            parts.append(f"  Process: {event['process_name']}")
        if event.get("command_line"):
            # Truncate very long command lines
            cmd = event["command_line"][:500]
            if len(event["command_line"]) > 500:
                cmd += "... [truncated]"
            parts.append(f"  Command: {cmd}")
        if event.get("parent_process_name"):
            parts.append(f"  Parent: {event['parent_process_name']}")
        if event.get("image_path"):
            parts.append(f"  Path: {event['image_path']}")
        if event.get("event_id"):
            parts.append(f"  Event ID: {event['event_id']}")
        
        # Network info if present
        if event.get("dest_ip"):
            parts.append(f"  Destination: {event['dest_ip']}:{event.get('dest_port', 'N/A')}")
        
        # File info if present
        if event.get("target_filename"):
            parts.append(f"  Target File: {event['target_filename']}")
        if event.get("file_hash"):
            parts.append(f"  Hash: {event['file_hash']}")
    
    # Add context
    parts.append("\n\n--- CONTEXT ---")
    parts.append(f"User: {request.context.user}")
    parts.append(f"Host: {request.context.host}")
    parts.append(f"Preliminary Rule Score: {request.rule_score}")
    
    if request.context.category:
        parts.append(f"Event Category: {request.context.category}")
    
    # Add baseline deviation if present
    if request.baseline_deviation:
        bd = request.baseline_deviation
        parts.append("\n--- BASELINE DEVIATION ---")
        deviations = []
        if bd.is_new_process:
            deviations.append("NEW_PROCESS (never seen before)")
        if bd.is_unusual_hour:
            deviations.append("UNUSUAL_HOUR (outside normal working hours)")
        if bd.is_rare_parent_child:
            deviations.append("RARE_PROCESS_CHAIN (unusual parent-child)")
        
        if deviations:
            parts.append(f"Anomalies: {', '.join(deviations)}")
        parts.append(f"Events in last 5 min: {bd.events_last_5min}")
        parts.append(f"Deviation Score: {bd.deviation_score}")
    
    # Add threat intel if present
    if request.threat_intel:
        ti = request.threat_intel
        parts.append("\n--- THREAT INTELLIGENCE ---")
        if ti.hash_reputation:
            parts.append(f"Hash Reputation: {ti.hash_reputation}")
        if ti.vt_positives is not None and ti.vt_total is not None:
            parts.append(f"VirusTotal: {ti.vt_positives}/{ti.vt_total} detections")
        if ti.ip_reputation:
            parts.append(f"IP Reputation: {ti.ip_reputation}")
        if ti.abuse_confidence is not None:
            parts.append(f"AbuseIPDB Confidence: {ti.abuse_confidence}%")
    
    parts.append("\n\n--- YOUR ANALYSIS (JSON only) ---")
    
    return "\n".join(parts)


def parse_llm_response(raw_response: str, request_id: str) -> Dict[str, Any]:
    """
    Parse LLM text response into structured dictionary.
    
    Attempts to extract JSON from the response, with fallback parsing
    for malformed responses.
    
    Args:
        raw_response: Raw text from Ollama
        request_id: Request ID for correlation
        
    Returns:
        Dictionary with label, score, confidence, reason, comment
    """
    # Default fallback values
    result = {
        "request_id": request_id,
        "label": "SUSPICIOUS",
        "score": 50,
        "confidence": 0.5,
        "reason": "Unable to parse LLM response",
        "comment": "The AI analysis could not be parsed. Manual review recommended.",
        "source": "ai_server",
        "error": None
    }
    
    # Clean up response - remove markdown code blocks if present
    cleaned = raw_response.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    if cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()
    
    # Try to parse as JSON
    try:
        parsed = json.loads(cleaned)
        
        # Extract and validate fields
        if "label" in parsed:
            label = parsed["label"].upper()
            if label in ["MALICIOUS", "SUSPICIOUS", "BENIGN"]:
                result["label"] = label
        
        if "score" in parsed:
            score = int(parsed["score"])
            result["score"] = max(0, min(100, score))
        
        if "confidence" in parsed:
            conf = float(parsed["confidence"])
            result["confidence"] = max(0.0, min(1.0, conf))
        
        if "reason" in parsed:
            result["reason"] = str(parsed["reason"])[:200]
        
        if "comment" in parsed:
            result["comment"] = str(parsed["comment"])[:1000]
        
        result["error"] = None
        
    except json.JSONDecodeError:
        # Fallback: try to extract key fields from text
        result["error"] = "JSON parse failed, used fallback parsing"
        
        upper_response = raw_response.upper()
        if "MALICIOUS" in upper_response:
            result["label"] = "MALICIOUS"
            result["score"] = 75
        elif "BENIGN" in upper_response:
            result["label"] = "BENIGN"
            result["score"] = 20
        
        # Try to extract a reason
        for line in raw_response.split("\n"):
            if "reason" in line.lower() or "because" in line.lower():
                result["reason"] = line.strip()[:200]
                break
    
    return result
