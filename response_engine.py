# /opt/soar-engine/response_engine.py
"""
Response execution engine.
Handles firewall blocking, user disabling, and action coordination.
All subprocess calls are validated against injection attacks.
"""
import asyncio
import ipaddress
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Optional
 
from config import get_settings
from logger import setup_logger, audit
 
logger = setup_logger("soar.response_engine")
settings = get_settings()
 
# ── Security: Only allow valid IPv4 addresses ─────────────────────────────────
IPV4_PATTERN = re.compile(
    r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)
 
# ── Security: Only allow alphanumeric usernames ────────────────────────────────
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,32}$')
 
 
@dataclass
class ResponseResult:
    """Result of an executed response action."""
    success: bool
    action: str
    target: str
    message: str
    timestamp: float = None
 
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
 
 
def _validate_ip(ip: str) -> str:
    """
    Validate and sanitize an IP address string.
    Raises ValueError if invalid. Returns the validated IP.
    """
    ip = ip.strip()
    if not IPV4_PATTERN.match(ip):
        raise ValueError(f"Invalid IPv4 address format: {ip!r}")
 
    # Additional check using Python's ipaddress module
    addr = ipaddress.IPv4Address(ip)
 
    # Prevent blocking of special-use addresses
    if addr.is_loopback:
        raise ValueError(f"Cannot block loopback address: {ip}")
    if addr.is_link_local:
        raise ValueError(f"Cannot block link-local address: {ip}")
    if addr.is_multicast:
        raise ValueError(f"Cannot block multicast address: {ip}")
 
    return str(addr)
 
 
def _run_command(cmd: list, alert_id: str, description: str) -> bool:
    """
    Execute a validated system command via subprocess.
    Uses a fixed command list (no shell=True) to prevent injection.
    """
    logger.info(f"[{alert_id}] Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,   # CRITICAL: Never use shell=True with user data
            check=False
        )
        if result.returncode == 0:
            logger.info(f"[{alert_id}] Command success: {description}")
            return True
        else:
            logger.error(
                f"[{alert_id}] Command failed (rc={result.returncode}): "
                f"{description}. stderr: {result.stderr[:200]}"
            )
            return False
    except subprocess.TimeoutExpired:
        logger.error(f"[{alert_id}] Command timeout: {description}")
        return False
    except FileNotFoundError as e:
        logger.error(f"[{alert_id}] Command not found: {e}")
        return False
    except Exception as e:
        logger.error(f"[{alert_id}] Unexpected error running command: {e}")
        return False
 
 
async def block_ip(ip: str, alert_id: str, comment: str = "SOAR-auto-block") -> ResponseResult:
    """
    Block an IP address using iptables INPUT and FORWARD chains.
    Validates IP before execution. Saves rules persistently.
    """
    try:
        validated_ip = _validate_ip(ip)
    except ValueError as e:
        msg = f"IP validation failed: {e}"
        logger.error(f"[{alert_id}] {msg}")
        audit.log_action(alert_id, "BLOCK_IP", ip, f"FAILED: {msg}")
        return ResponseResult(success=False, action="BLOCK_IP", target=ip, message=msg)
 
    # Block on INPUT chain (inbound connections)
    input_ok = _run_command(
        ["iptables", "-I", "INPUT", "-s", validated_ip, "-j", "DROP",
         "-m", "comment", "--comment", f"{comment}-{alert_id[:8]}"],
        alert_id, f"iptables INPUT DROP {validated_ip}"
    )
 
    # Block on FORWARD chain (routed traffic)
    forward_ok = _run_command(
        ["iptables", "-I", "FORWARD", "-s", validated_ip, "-j", "DROP",
         "-m", "comment", "--comment", f"{comment}-{alert_id[:8]}"],
        alert_id, f"iptables FORWARD DROP {validated_ip}"
    )
 
    # Save iptables rules persistently
    _run_command(
        ["netfilter-persistent", "save"],
        alert_id, "Save iptables rules"
    )
 
    success = input_ok and forward_ok
    msg = f"IP {validated_ip} {'blocked successfully' if success else 'block FAILED'}"
 
    audit.log_action(alert_id, "BLOCK_IP", validated_ip, "SUCCESS" if success else "FAILED")
    logger.info(f"[{alert_id}] {msg}")
 
    # Schedule unblock after configured duration
    if success and settings.block_duration_hours > 0:
        asyncio.create_task(_schedule_unblock(validated_ip, alert_id, settings.block_duration_hours))
 
    return ResponseResult(success=success, action="BLOCK_IP", target=validated_ip, message=msg)
 
 
async def _schedule_unblock(ip: str, alert_id: str, hours: int):
    """Automatically unblock an IP after the specified duration."""
    delay_seconds = hours * 3600
    logger.info(f"[{alert_id}] Scheduled unblock for {ip} in {hours} hours")
    await asyncio.sleep(delay_seconds)
    await unblock_ip(ip, alert_id, reason="scheduled_auto_expiry")
 
 
async def unblock_ip(ip: str, alert_id: str, reason: str = "manual") -> ResponseResult:
    """Remove an IP block from iptables."""
    try:
        validated_ip = _validate_ip(ip)
    except ValueError as e:
        msg = f"IP validation failed: {e}"
        return ResponseResult(success=False, action="UNBLOCK_IP", target=ip, message=msg)
 
    # Remove from INPUT chain
    input_ok = _run_command(
        ["iptables", "-D", "INPUT", "-s", validated_ip, "-j", "DROP"],
        alert_id, f"iptables DELETE INPUT {validated_ip}"
    )
 
    # Remove from FORWARD chain
    forward_ok = _run_command(
        ["iptables", "-D", "FORWARD", "-s", validated_ip, "-j", "DROP"],
        alert_id, f"iptables DELETE FORWARD {validated_ip}"
    )
 
    _run_command(["netfilter-persistent", "save"], alert_id, "Save iptables rules")
 
    success = input_ok or forward_ok
    msg = f"IP {validated_ip} unblocked ({reason})"
    audit.log_action(alert_id, "UNBLOCK_IP", validated_ip, "SUCCESS" if success else "PARTIAL")
    return ResponseResult(success=success, action="UNBLOCK_IP", target=validated_ip, message=msg)
 
 
async def disable_user(username: str, alert_id: str) -> ResponseResult:
    """
    Disable a local Linux user account.
    Validates username to prevent command injection.
    """
    if not USERNAME_PATTERN.match(username):
        msg = f"Invalid username format: {username!r}"
        logger.error(f"[{alert_id}] {msg}")
        return ResponseResult(success=False, action="DISABLE_USER", target=username, message=msg)
 
    # Lock the user account
    ok = _run_command(
        ["usermod", "--lock", username],
        alert_id, f"Lock user account: {username}"
    )
 
    if ok:
        # Kill existing sessions
        _run_command(
            ["pkill", "-TERM", "-u", username],
            alert_id, f"Kill sessions for {username}"
        )
 
    msg = f"User {username} {'disabled' if ok else 'disable FAILED'}"
    audit.log_action(alert_id, "DISABLE_USER", username, "SUCCESS" if ok else "FAILED")
    return ResponseResult(success=ok, action="DISABLE_USER", target=username, message=msg)
 
 
async def execute_response(action: str, target: str, alert_id: str) -> ResponseResult:
    """
    Main response dispatcher. Routes the action to the appropriate handler.
    """
    logger.info(f"[{alert_id}] Executing response: action={action}, target={target}")
 
    if action == "BLOCK_IP":
        return await block_ip(target, alert_id)
    elif action == "UNBLOCK_IP":
        return await unblock_ip(target, alert_id)
    elif action == "DISABLE_USER":
        return await disable_user(target, alert_id)
    elif action in ("ESCALATE", "ALERT_ONLY", "IGNORE"):
        # No automated system action; handled by notification layer
        audit.log_action(alert_id, action, target, "LOGGED")
        return ResponseResult(success=True, action=action, target=target,
                             message=f"Action {action} logged. No system change applied.")
    else:
        msg = f"Unknown action: {action}"
        logger.error(f"[{alert_id}] {msg}")
        return ResponseResult(success=False, action=action, target=target, message=msg)
