# /opt/soar-engine/decision_engine.py
"""
Decision engine: maps AI analysis + enrichment data to a final action.
Implements weighted scoring with override rules for safety.
"""
from dataclasses import dataclass
from typing import Any, Dict, Optional
 
from config import get_settings
from logger import setup_logger
from threat_intel import IPReputationResult
from ai_engine import AIAnalysisResult
 
logger = setup_logger("soar.decision_engine")
settings = get_settings()
 
 
@dataclass
class DecisionResult:
    """Final decision produced by the decision engine."""
    action: str                      # BLOCK_IP | ESCALATE | ALERT_ONLY | IGNORE
    final_score: float               # Composite score 0-100
    reason: str                      # Human-readable decision rationale
    override_applied: bool = False   # True if a safety override was triggered
    is_whitelisted: bool = False
 
 
# Severity weights for score calculation
SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFO": 5,
}
 
# Action thresholds
ACTION_MAP = [
    (90, "BLOCK_IP"),        # Score >= 90 -> Block
    (70, "BLOCK_IP"),        # Score >= 70 -> Block (with AI recommendation)
    (50, "ESCALATE"),        # Score >= 50 -> Escalate
    (20, "ALERT_ONLY"),      # Score >= 20 -> Alert
    (0,  "IGNORE"),          # Score < 20  -> Ignore
]
 
 
def calculate_final_score(
    ai_result: AIAnalysisResult,
    ip_rep: Optional[IPReputationResult]
) -> float:
    """
    Compute a composite threat score using AI severity and enrichment data.
 
    Weights:
    - AI severity:          40%
    - AI confidence:        20%
    - IP composite score:   30%
    - Reports count bonus:  10%
    """
    # AI contribution
    ai_severity_score = SEVERITY_SCORES.get(ai_result.severity, 50)
    ai_confidence_normalized = ai_result.confidence  # Already 0-100
 
    ai_component = (ai_severity_score * 0.4) + (ai_confidence_normalized * 0.2)
 
    # Enrichment contribution
    enrichment_component = 0.0
    if ip_rep and not ip_rep.error:
        enrichment_component = ip_rep.confidence_score * 0.3
 
        # Bonus for high report count (strong community signal)
        if ip_rep.abuse_reports_count > 1000:
            enrichment_component += 10 * 0.1
        elif ip_rep.abuse_reports_count > 100:
            enrichment_component += 5 * 0.1
 
    total = ai_component + enrichment_component
    return min(round(total, 2), 100.0)
 
 
def determine_action(score: float, ai_result: AIAnalysisResult) -> str:
    """Map a score to an action, factoring in AI recommendation."""
    # If AI recommends blocking and score agrees, block
    if ai_result.recommended_action == "BLOCK_IP" and score >= settings.block_score_threshold:
        return "BLOCK_IP"
 
    # If AI recommends escalate and score agrees, escalate
    if ai_result.recommended_action == "ESCALATE" and score >= settings.escalate_score_threshold:
        return "ESCALATE"
 
    # Score-based fallback
    for threshold, action in ACTION_MAP:
        if score >= threshold:
            return action
 
    return "ALERT_ONLY"
 
 
def make_decision(
    alert: Dict[str, Any],
    ai_result: AIAnalysisResult,
    ip_rep: Optional[IPReputationResult] = None
) -> DecisionResult:
    """
    Primary decision function. Evaluates all signals and returns a final action.
    Applies safety overrides to prevent blocking whitelisted or private IPs.
    """
    src_ip = (alert.get("data", {}).get("srcip") or
              alert.get("data", {}).get("src_ip") or
              alert.get("decoder", {}).get("srcip"))
 
    # ── Safety Override 1: Whitelist check ───────────────────────────────────
    if src_ip and settings.is_whitelisted(src_ip):
        logger.info(f"Decision OVERRIDE: {src_ip} is in whitelist. Action: ALERT_ONLY")
        return DecisionResult(
            action="ALERT_ONLY",
            final_score=0,
            reason=f"IP {src_ip} is in the configured whitelist. No automated block.",
            override_applied=True,
            is_whitelisted=True
        )
 
    # ── Safety Override 2: Auto-block disabled ────────────────────────────────
    if not settings.enable_auto_block:
        score = calculate_final_score(ai_result, ip_rep)
        logger.info(f"Auto-block disabled. Score={score}. Downgrading to ALERT_ONLY.")
        return DecisionResult(
            action="ALERT_ONLY",
            final_score=score,
            reason="Auto-block is disabled in configuration. Alert sent for manual review.",
            override_applied=True
        )
 
    # ── Safety Override 3: AI error fallback ─────────────────────────────────
    if ai_result.error:
        logger.warning(f"AI engine returned error. Falling back to ALERT_ONLY: {ai_result.error}")
        score = ip_rep.confidence_score if ip_rep and not ip_rep.error else 0
        return DecisionResult(
            action="ALERT_ONLY",
            final_score=score,
            reason=f"AI analysis failed ({ai_result.error}). Manual investigation required.",
            override_applied=True
        )
 
    # ── Normal decision path ──────────────────────────────────────────────────
    score = calculate_final_score(ai_result, ip_rep)
    action = determine_action(score, ai_result)
 
    reason = (
        f"Composite score {score}/100. "
        f"AI severity: {ai_result.severity} (confidence {ai_result.confidence}%). "
        f"IP threat score: {ip_rep.confidence_score if ip_rep else 'N/A'}. "
        f"Action: {action}. AI reasoning: {ai_result.reasoning[:200]}"
    )
 
    logger.info(
        f"Decision: action={action}, score={score}, "
        f"ai_severity={ai_result.severity}, ip={src_ip}"
    )
 
    return DecisionResult(action=action, final_score=score, reason=reason)
