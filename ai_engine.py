# /opt/soar-engine/ai_engine.py
"""
AI analysis engine supporting OpenAI GPT-4 (primary) and Ollama (local fallback).
Constructs structured security analysis prompts and parses JSON responses.
"""
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional
 
import httpx
from openai import AsyncOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential
 
from config import get_settings
from logger import setup_logger
from threat_intel import IPReputationResult, HashReputationResult
 
logger = setup_logger("soar.ai_engine")
settings = get_settings()
 
 
@dataclass
class AIAnalysisResult:
    """Structured output from AI alert analysis."""
    severity: str = "MEDIUM"          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: int = 50              # 0-100 AI confidence in its assessment
    threat_classification: str = "Unknown"
    mitre_tactic: str = "Unknown"
    narrative: str = ""
    recommended_action: str = "ALERT_ONLY"  # BLOCK_IP | ESCALATE | ALERT_ONLY | IGNORE
    reasoning: str = ""
    raw_response: str = ""
    model_used: str = ""
    error: Optional[str] = None
 
 
SYSTEM_PROMPT = """You are an expert cybersecurity analyst integrated into a Security Operations Center (SOC).
You analyze security alerts from Wazuh SIEM and threat intelligence data to classify threats and recommend responses.
 
Your analysis must be:
- Precise and based only on the data provided
- Actionable with clear severity reasoning
- MITRE ATT&CK aligned where applicable
- Aware of false positive patterns (legitimate admin activity, scanner noise)
 
SEVERITY DEFINITIONS:
- CRITICAL: Active attack, confirmed malware, data exfiltration. Immediate response required.
- HIGH: Strong indicators of attack, multiple detection signals, needs fast investigation.
- MEDIUM: Suspicious activity, single indicator, warrants investigation within hours.
- LOW: Policy violation, anomaly, low risk. Log and monitor.
- INFO: Informational, likely benign. No action needed.
 
ACTION DEFINITIONS:
- BLOCK_IP: Immediately block the source IP via firewall (use for CRITICAL/HIGH with confirmed bad IP).
- ESCALATE: Page on-call analyst immediately (use for CRITICAL events needing human judgment).
- ALERT_ONLY: Send Slack notification, log for investigation. No automated block.
- IGNORE: Suppress and mark as false positive. Do not alert.
 
RESPONSE FORMAT: You MUST respond with ONLY valid JSON, no markdown, no explanation outside JSON:
{
  "severity": "HIGH",
  "confidence": 85,
  "threat_classification": "SSH Brute Force - Credential Access",
  "mitre_tactic": "Credential Access (T1110)",
  "narrative": "Source IP 1.2.3.4 has made 47 failed SSH login attempts in 3 minutes targeting root and admin accounts. AbuseIPDB reports 78/100 abuse confidence with 340 prior reports. This is consistent with an automated credential stuffing attack.",
  "recommended_action": "BLOCK_IP",
  "reasoning": "High abuse confidence score (78), large number of rapid failed attempts, targeting privileged accounts. Automated block is appropriate."
}"""
 
 
def build_alert_prompt(
    alert: Dict[str, Any],
    ip_rep: Optional[IPReputationResult] = None,
    hash_rep: Optional[HashReputationResult] = None
) -> str:
    """
    Construct a structured analysis prompt from alert data and enrichment results.
    """
    prompt_parts = [
        "## SECURITY ALERT FOR ANALYSIS",
        "",
        f"**Rule ID:** {alert.get('rule', {}).get('id', 'N/A')}",
        f"**Rule Description:** {alert.get('rule', {}).get('description', 'N/A')}",
        f"**Severity Level (Wazuh):** {alert.get('rule', {}).get('level', 0)}/15",
        f"**Agent Hostname:** {alert.get('agent', {}).get('name', 'Unknown')}",
        f"**Agent IP:** {alert.get('agent', {}).get('ip', 'Unknown')}",
        f"**Timestamp:** {alert.get('timestamp', 'Unknown')}",
        f"**Rule Groups:** {', '.join(alert.get('rule', {}).get('groups', []))}",
        "",
        "## ALERT DETAILS",
        f"**Full Log:** {alert.get('full_log', alert.get('data', {}).get('win', {}).get('system', {}).get('message', 'N/A'))[:500]}",
    ]
 
    # Source IP context
    src_ip = (alert.get("data", {}).get("srcip") or
              alert.get("data", {}).get("src_ip") or
              alert.get("decoder", {}).get("srcip"))
 
    if src_ip:
        prompt_parts.extend([
            "",
            "## SOURCE IP INTELLIGENCE",
            f"**Source IP:** {src_ip}",
        ])
 
        if ip_rep and not ip_rep.error:
            prompt_parts.extend([
                f"**AbuseIPDB Confidence:** {ip_rep.abuse_confidence}/100",
                f"**Prior Abuse Reports:** {ip_rep.abuse_reports_count}",
                f"**Country:** {ip_rep.country_code}",
                f"**ISP:** {ip_rep.isp}",
                f"**TOR Exit Node:** {ip_rep.is_tor}",
                f"**VirusTotal Malicious Detections:** {ip_rep.vt_malicious}/{ip_rep.vt_total_engines}",
                f"**Composite Threat Score:** {ip_rep.confidence_score}/100",
            ])
        else:
            prompt_parts.append("**Threat Intel:** Unavailable (API error or rate limited)")
 
    # File hash context
    file_hash = alert.get("syscheck", {}).get("sha256_after") or alert.get("data", {}).get("md5")
    if file_hash and hash_rep and not hash_rep.error:
        prompt_parts.extend([
            "",
            "## FILE HASH INTELLIGENCE",
            f"**Hash:** {file_hash}",
            f"**VirusTotal Malicious:** {hash_rep.malicious}/{hash_rep.total}",
            f"**Threat Name:** {hash_rep.threat_name or 'Unknown'}",
            f"**Hash Score:** {hash_rep.confidence_score}/100",
        ])
 
    # MITRE context
    mitre_ids = alert.get("rule", {}).get("mitre", {}).get("id", [])
    if mitre_ids:
        prompt_parts.extend([
            "",
            "## MITRE ATT&CK",
            f"**Technique IDs:** {', '.join(mitre_ids)}",
        ])
 
    prompt_parts.extend([
        "",
        "## TASK",
        "Analyze this alert and provide your assessment as JSON. Consider all threat intel data."
        "Be conservative with BLOCK actions - only recommend for clearly malicious, non-whitelisted IPs."
    ])
 
    return "\n".join(prompt_parts)
 
 
class OpenAIEngine:
    """OpenAI GPT-4 analysis engine."""
 
    def __init__(self):
        self.client = AsyncOpenAI(
            api_key=settings.openai_api_key,
            timeout=settings.openai_timeout,
        )
 
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=20),
    )
    async def analyze(self, prompt: str) -> AIAnalysisResult:
        """Submit alert to OpenAI and parse the structured response."""
        result = AIAnalysisResult(model_used=settings.openai_model)
 
        try:
            response = await self.client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,       # Low temperature for consistent analysis
                max_tokens=1000,
                response_format={"type": "json_object"},  # Force JSON output
            )
 
            raw = response.choices[0].message.content or ""
            result.raw_response = raw
 
            # Parse and validate JSON response
            parsed = json.loads(raw)
            result.severity = parsed.get("severity", "MEDIUM").upper()
            result.confidence = int(parsed.get("confidence", 50))
            result.threat_classification = parsed.get("threat_classification", "Unknown")
            result.mitre_tactic = parsed.get("mitre_tactic", "Unknown")
            result.narrative = parsed.get("narrative", "")
            result.recommended_action = parsed.get("recommended_action", "ALERT_ONLY").upper()
            result.reasoning = parsed.get("reasoning", "")
 
            # Validate severity and action values
            valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            valid_actions = {"BLOCK_IP", "ESCALATE", "ALERT_ONLY", "IGNORE"}
 
            if result.severity not in valid_severities:
                result.severity = "MEDIUM"
            if result.recommended_action not in valid_actions:
                result.recommended_action = "ALERT_ONLY"
 
            logger.info(f"AI analysis complete: severity={result.severity}, action={result.recommended_action}, confidence={result.confidence}")
 
        except json.JSONDecodeError as e:
            logger.error(f"AI returned invalid JSON: {e}. Raw: {raw[:200]}")
            result.error = f"json_parse_error: {e}"
            result.severity = "MEDIUM"
            result.recommended_action = "ALERT_ONLY"
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            result.error = str(e)
            raise
 
        return result
 
 
class OllamaEngine:
    """Local Ollama LLM engine for air-gapped or cost-optimized deployments."""
 
    def __init__(self):
        self.host = settings.ollama_host
        self.model = settings.ollama_model
 
    async def analyze(self, prompt: str) -> AIAnalysisResult:
        """Submit alert to Ollama local LLM."""
        result = AIAnalysisResult(model_used=f"ollama/{self.model}")
        full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}\n\nRespond with ONLY valid JSON:"
 
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{self.host}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": full_prompt,
                        "stream": False,
                        "options": {"temperature": 0.1, "num_predict": 1000}
                    }
                )
                response.raise_for_status()
                raw = response.json().get("response", "")
                result.raw_response = raw
 
                # Extract JSON from response (Ollama may include preamble)
                json_match = re.search(r'\{.*\}', raw, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group())
                    result.severity = parsed.get("severity", "MEDIUM").upper()
                    result.confidence = int(parsed.get("confidence", 50))
                    result.threat_classification = parsed.get("threat_classification", "Unknown")
                    result.mitre_tactic = parsed.get("mitre_tactic", "Unknown")
                    result.narrative = parsed.get("narrative", "")
                    result.recommended_action = parsed.get("recommended_action", "ALERT_ONLY").upper()
                    result.reasoning = parsed.get("reasoning", "")
                else:
                    raise ValueError("No JSON found in Ollama response")
 
        except Exception as e:
            logger.error(f"Ollama analysis failed: {e}")
            result.error = str(e)
            result.severity = "MEDIUM"
            result.recommended_action = "ALERT_ONLY"
 
        return result
 
 
async def analyze_alert(
    alert: Dict[str, Any],
    ip_rep: Optional[IPReputationResult] = None,
    hash_rep: Optional[HashReputationResult] = None
) -> AIAnalysisResult:
    """
    Main entry point for AI alert analysis.
    Uses configured provider with automatic fallback to Ollama on error.
    """
    prompt = build_alert_prompt(alert, ip_rep, hash_rep)
 
    if settings.ai_provider == "openai" and settings.openai_api_key:
        engine = OpenAIEngine()
        try:
            result = await engine.analyze(prompt)
            if not result.error:
                return result
            logger.warning(f"OpenAI failed, attempting Ollama fallback: {result.error}")
        except Exception as e:
            logger.warning(f"OpenAI unavailable: {e}. Falling back to Ollama.")
 
    # Fallback to Ollama
    engine = OllamaEngine()
    return await engine.analyze(prompt)
