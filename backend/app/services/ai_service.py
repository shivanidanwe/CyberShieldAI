"""CyberShield AI — local, dependency-free AI layer.

Three capabilities, all implemented with the Python standard library so the
platform runs offline with no API keys:

1. ``AnomalyDetector`` — a pure-Python Isolation Forest that scores packets for
   statistical deviation from a learned baseline.
2. ``explain_alert`` — structured, readable explanations for security alerts.
3. ``assistant_respond`` — a deterministic SOC assistant that answers questions
   about the live security posture using dashboard context.

If an Anthropic API key is provided (``CYBERSHIELD_ANTHROPIC_API_KEY``), the
assistant upgrades to a Claude-generated reply; otherwise it stays local.
"""

from __future__ import annotations

import logging
import random
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from app.database import SessionLocal
from app.models import Alert, Packet
from app.utils.logger import get_logger

logger = get_logger("ai")

# ----------------------------------------------------------------------------
# Isolation Forest internals (pure Python)
# ----------------------------------------------------------------------------


def _harmonic(number: int) -> float:
    return sum(1.0 / i for i in range(1, number + 1))


def _avg_path_length(number: int) -> float:
    """Expected path length of an unsuccessful search in a BST with n nodes."""
    if number <= 1:
        return 0.0
    if number == 2:
        return 1.0
    return 2.0 * _harmonic(number - 1) - 2.0 * (number - 1) / number


class _IsolationTreeNode:
    __slots__ = ("size", "split_feature", "split_value", "left", "right", "is_leaf")

    def __init__(self) -> None:
        self.size = 0
        self.split_feature: Optional[int] = None
        self.split_value: float = 0.0
        self.left: Optional["_IsolationTreeNode"] = None
        self.right: Optional["_IsolationTreeNode"] = None
        self.is_leaf = True

    def build(self, rows: List[List[float]], depth: int, max_depth: int, rng: random.Random) -> None:
        self.size = len(rows)
        if depth >= max_depth or self.size <= 1:
            return

        variable_features = [
            feature
            for feature in range(len(rows[0]))
            if len({row[feature] for row in rows}) > 1
        ]
        if not variable_features:
            return

        self.split_feature = rng.choice(variable_features)
        values = [row[self.split_feature] for row in rows]
        low, high = min(values), max(values)
        if low == high:
            return

        self.split_value = rng.uniform(low, high)
        left_rows = [row for row in rows if row[self.split_feature] < self.split_value]
        right_rows = [row for row in rows if row[self.split_feature] >= self.split_value]

        if not left_rows or not right_rows:
            return

        self.is_leaf = False
        self.left = _IsolationTreeNode()
        self.left.build(left_rows, depth + 1, max_depth, rng)
        self.right = _IsolationTreeNode()
        self.right.build(right_rows, depth + 1, max_depth, rng)

    def path_length(self, point: List[float]) -> float:
        node = self
        length = 0.0
        while not node.is_leaf:
            if point[node.split_feature] < node.split_value:  # type: ignore[arg-type]
                node = node.left  # type: ignore[assignment]
            else:
                node = node.right  # type: ignore[assignment]
            length += 1.0
        return length + _avg_path_length(node.size)


class AnomalyDetector:
    """Isolation Forest anomaly scorer over numeric packet features."""

    FEATURES = ("destination_port", "packet_length", "protocol", "source_port")

    def __init__(
        self,
        n_estimators: int = 64,
        max_depth: int = 12,
        sample_size: int = 96,
        seed: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.sample_size = sample_size
        self.seed = seed
        self._rng = random.Random(seed)

    # -- feature engineering -------------------------------------------------

    @staticmethod
    def _protocol_number(protocol: Optional[str]) -> float:
        return {
            "TCP": 6.0,
            "UDP": 17.0,
            "ICMP": 1.0,
        }.get((protocol or "").upper(), 0.0)

    def _to_row(self, packet: Dict[str, Any]) -> List[float]:
        return [
            float(packet.get("destination_port") or 0),
            float(packet.get("packet_length") or 0),
            self._protocol_number(packet.get("protocol")),
            float(packet.get("source_port") or 0),
        ]

    # -- scoring -------------------------------------------------------------

    def score(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return a copy of each packet augmented with an anomaly 'score'."""
        if not packets:
            return []

        rows = [self._to_row(packet) for packet in packets]
        n = len(rows)
        sample_m = min(self.sample_size, n)
        c_sample = _avg_path_length(sample_m)

        trees: List[_IsolationTreeNode] = []
        for _ in range(self.n_estimators):
            indices = self._rng.sample(range(n), sample_m)
            sample = [rows[i] for i in indices]
            tree = _IsolationTreeNode()
            tree.build(sample, 0, self.max_depth, self._rng)
            trees.append(tree)

        scored = []
        for i, packet in enumerate(packets):
            path_sums = 0.0
            for tree in trees:
                path_sums += tree.path_length(rows[i])
            expected_path = path_sums / max(len(trees), 1)
            anomaly_score = 2.0 ** (-expected_path / c_sample) if c_sample > 0 else 0.0
            item = dict(packet)
            item["score"] = round(anomaly_score, 4)
            scored.append(item)

        return scored

    # -- feature insight -----------------------------------------------------

    def _explain_outlier(self, packet: Dict[str, Any], scored: List[Dict[str, Any]]) -> str:
        reasons = []
        if packet.get("packet_length") and scored:
            lengths = [float(p.get("packet_length") or 0) for p in scored]
            mean = sum(lengths) / len(lengths)
            std = (sum((v - mean) ** 2 for v in lengths) / len(lengths)) ** 0.5 or 1.0
            z = abs(packet["packet_length"] - mean) / std
            if z >= 2.0:
                reasons.append(f"packet size ({packet['packet_length']}B) is {z:.1f}σ above baseline")
        if packet.get("destination_port") and scored:
            ports = [float(p.get("destination_port") or 0) for p in scored if p.get("destination_port")]
            if ports and packet["destination_port"] not in ports[: max(1, len(ports) // 2)]:
                reasons.append(f"destination port {packet['destination_port']} is rare in recent traffic")
        if not reasons:
            reasons.append("combined feature profile is unusual relative to the learned baseline")
        return "; ".join(reasons)

    # -- public scan ---------------------------------------------------------

    def scan(
        self,
        packets: List[Dict[str, Any]],
        threshold: float = 0.62,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Score packets and flag the most anomalous ones."""
        scored = self.score(packets)
        if not scored:
            return {"result": "ok", "scanned": 0, "anomalies": [], "analyzed_at": datetime.utcnow().isoformat()}

        flagged = [p for p in scored if p["score"] >= threshold]
        flagged.sort(key=lambda p: p["score"], reverse=True)
        flagged = flagged[:limit]

        anomalies = []
        for item in flagged:
            anomalies.append(
                {
                    **{k: item.get(k) for k in ("source_ip", "destination_ip", "protocol", "source_port", "destination_port", "packet_length")},
                    "score": item.get("score"),
                    "reason": self._explain_outlier(item, scored),
                    "recommendation": _outlier_recommendation(item),
                }
            )

        avg_score = sum(p["score"] for p in scored) / len(scored)
        return {
            "result": "ok",
            "scanned": len(scored),
            "anomalies": anomalies,
            "threshold": threshold,
            "average_score": round(avg_score, 4),
            "baseline": {
                "n_estimators": self.n_estimators,
                "sample_size": min(self.sample_size, len(scored)),
            },
            "analyzed_at": datetime.utcnow().isoformat(),
        }


def _outlier_recommendation(packet: Dict[str, Any]) -> str:
    protocol = (packet.get("protocol") or "").upper()
    port = packet.get("destination_port")
    if protocol == "ICMP":
        return "Inspect the source — repeated oversized ICMP is often a flood or covert-channel attempt."
    if port in (23, 21, 3389, 445, 22):
        return f"Unusual access to an administrative service on port {port} — review the source host and disable the service if unneeded."
    if (packet.get("packet_length") or 0) > 1500:
        return "Oversized frames may indicate tunneling or bulk data exfiltration — capture the payload and correlate with alerts."
    return "Contrast this flow against the baseline; consider isolating the source and correlating with endpoint telemetry."


# ----------------------------------------------------------------------------
# Alert explanation knowledge base
# ----------------------------------------------------------------------------

_ATTACK_KB: Dict[str, Dict[str, str]] = {
    "Telnet Access": {
        "summary": "An attempt to connect to the Telnet service, which carries credentials and sessions in cleartext.",
        "why": "The packet targeted TCP port 23, the standard Telnet port. Telnet is universally considered unsafe because passwords and commands travel unencrypted.",
        "intent": "The actor may be probing for a login, capturing credentials sniffing the link, or moving laterally once access is gained.",
        "recommended": "Block port 23 at the firewall; migrate any management traffic to SSH with key-only authentication; enforce MFA.",
    },
    "FTP Access": {
        "summary": "Traffic to an FTP service, which transmits credentials and data without encryption.",
        "why": "The packet reached TCP port 21. Plaintext FTP exposes usernames and passwords to anyone observing the link.",
        "intent": "Credential harvesting or secure sharing of stolen data through a service that legacy devices still trust.",
        "recommended": "Disable FTP; use SFTP/FTPS; add egress rules so FTP only talks to approved hosts.",
    },
    "SSH Access": {
        "summary": "Traffic to the SSH administration service.",
        "why": "The packet targeted TCP port 22. SSH is legitimate but is also the most common target of brute-force login attempts.",
        "intent": "Password spraying or credential-stuffing against an interactive login shell.",
        "recommended": "Rate-limit login attempts, disable password auth for remote users, use keys + MFA, and geo/firewall allowlist source ranges.",
    },
    "Remote Desktop": {
        "summary": "Access to the Windows Remote Desktop service.",
        "why": "The packet reached TCP port 3389. RDP exposed to a network invites brute force and known-certificate attacks.",
        "intent": "Attempting to take over an interactive Windows session for lateral movement or persistence.",
        "recommended": "Restrict RDP to a VPN/allowlist, enable NLA, use strong credentials, and monitor for repeated 3389 attempts.",
    },
    "SMB Access": {
        "summary": "Traffic to the Windows file-sharing service (Server Message Block).",
        "why": "The packet reached TCP port 445. SMB is frequently abused for ransomware, credential theft, and EternalBlue-style exploits.",
        "intent": "Mapping shares, stealing credentials, or staging an SMB-based exploit against the endpoint.",
        "recommended": "Patch SMB-facing hosts, restrict 445 egress, and require authenticated access only.",
    },
    "ICMP Flood": {
        "summary": "An unusually large ICMP packet, the signature of a flood or tunneling attempt.",
        "why": "ICMP control messages should be small. Sizes beyond the threshold deviate strongly from normal 'ping' activity.",
        "intent": "Denial of service against the target, or encapsulating data inside ICMP to evade filters.",
        "recommended": "Rate-limit ICMP at the edge, monitor source IPs for high-volume pings, and treat large echo replies as suspicious.",
    },
    "Large Packet": {
        "summary": "A packet larger than common MTU limits, an indication of probing or payload transfer.",
        "why": "Standard traffic respects the 1500-byte Ethernet MTU. Larger frames are rare and deserve inspection.",
        "intent": "Probing network behaviour, or transferring a fragment/bulk payload that normal rules might overlook.",
        "recommended": "Sample and inspect the payload, confirm whether the destination is authorized to receive bulk data, and raise the alert if repeated.",
    },
    "Port Scan": {
        "summary": "A single source touched many distinct destination ports in a short window — classic reconnaissance.",
        "why": "Legitimate clients connect to a handful of known services; sweeping many ports reveals the target's attack surface.",
        "intent": "Determining which services exist so a follow-up exploit can be aimed precisely.",
        "recommended": "Block the scanner at the perimeter, add an IDS rule for the pattern, and sweep logs for later hits from the same IP.",
    },
    "Anomaly": {
        "summary": "Machine learning flagged this flow as a statistical outlier versus the learned traffic baseline.",
        "why": "An Isolation Forest scored the packet's feature profile above the anomaly threshold—size, ports, or protocol mix diverged from normal.",
        "intent": "Could be a new internal behaviour or early reconnaissance that signature rules do not yet describe.",
        "recommended": "Review the flagged features, correlate with endpoint logs, and raise severity if it repeats across sources.",
    },
}

_DEFAULT_KB = _ATTACK_KB["Anomaly"]


def _knowledge_for(alert: Dict[str, Any]) -> Dict[str, str]:
    attack_type = alert.get("attack_type") or ""
    for key, value in _ATTACK_KB.items():
        if key.lower() in attack_type.lower():
            return value
    return _DEFAULT_KB


def explain_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Return a structured, human-readable explanation for an alert."""
    kb = _knowledge_for(alert)
    severity = (alert.get("severity") or "MEDIUM").upper()
    base = {
        "LOW": 0.25,
        "MEDIUM": 0.55,
        "HIGH": 0.85,
        "CRITICAL": 0.95,
    }
    confidence = round(min(base.get(severity, 0.55) + 0.08, 0.98), 2)

    description = alert.get("description")
    summary = kb["summary"]
    if description:
        summary = f"{summary} ({description})"

    return {
        "alert_id": alert.get("id"),
        "attack_type": alert.get("attack_type"),
        "severity": severity,
        "source_ip": alert.get("source_ip"),
        "destination_ip": alert.get("destination_ip"),
        "timestamp": alert.get("timestamp"),
        "confidence": confidence,
        "summary": summary,
        "why_flagged": kb["why"],
        "attacker_intent": kb["intent"],
        "recommended_actions": kb["recommended"],
        "extended_description": description,
    }


def explain_alert_text(alert: Dict[str, Any]) -> str:
    """Render an explanation as readable prose for chat/console contexts."""
    e = explain_alert(alert)
    lines = [
        f"**{e['attack_type']}** ({e['severity']}) — {e['summary']}",
        "",
        f"- Why flagged: {e['why_flagged']}",
        f"- Likely intent: {e['attacker_intent']}",
        f"- Recommended actions: {e['recommended_actions']}",
    ]
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# SOC assistant (deterministic, offline)
# ----------------------------------------------------------------------------

_CAPABILITIES = (
    "I can summarize what is happening ({q: dashboard})",
    "• List the latest alerts and their severity",
    "• Show high/critical alerts and the most targeted sources/hosts",
    "• Explain any alert — what it means and what to do",
    "• Run an AI anomaly scan over recent traffic",
    "• Report protocol mix and traffic/alert counts",
)


def _assistant_local(message: str, context: Dict[str, Any]) -> str:
    text = message.strip().lower()

    greetings = ("hi", "hello", "hey", "good morning", "good afternoon")
    if text in greetings or text == "":
        return (
            "Hello! I'm the CyberShield SOC assistant. I can summarize security posture, "
            "explain alerts, and recommend mitigations.\n\nWhat would you like to know?"
        )

    if any(word in text for word in ("help", "what can you do", "about", "capabilities")):
        return "Here's what I can help with:\n" + "\n".join(_CAPABILITIES)

    if any(word in text for word in ("overview", "summary", "status", "what's happening", "what is happening", "posture", "situation")):
        stats = context.get("stats", {})
        total_alerts = stats.get("total_alerts", 0)
        high = sum(
            count
            for severity, count in (stats.get("severity_breakdown") or {}).items()
            if str(severity).upper() in ("HIGH", "CRITICAL")
        )
        return (
            f"The network has recorded {stats.get('total_packets', 0)} packets and {total_alerts} alerts. "
            f"{high} of those alerts are high/critical severity. The most common protocol is "
            f"{_top_protocol(context)}. Threat posture is {_posture_label(context)}."
        )

    if any(word in text for word in ("latest", "recent", "new alerts", "last alert")):
        recent = context.get("recent_alerts", []) or []
        if not recent:
            return "There are no alerts in the log yet. Submit a packet or run a capture to generate activity."
        lines = ["Recent alerts:"]
        for alert in recent[:5]:
            lines.append(
                f"- [{alert.get('severity')}] {alert.get('attack_type')} from {alert.get('source_ip')} "
                f"to {alert.get('destination_ip')} ({_friendly_time(alert.get('timestamp'))})"
            )
        return "\n".join(lines)

    if any(word in text for word in ("high", "critical", "severe", "worst")):
        recent = context.get("recent_alerts", []) or []
        critical = [a for a in recent if str(a.get("severity") or "").upper() in ("HIGH", "CRITICAL")]
        if not critical:
            return "Good news — there are no high/critical alerts in recent activity."
        lines = [f"{len(critical)} high/critical alert(s) recently:"]
        for alert in critical:
            lines.append(f"- {alert.get('attack_type')} → {alert.get('destination_ip')} from {alert.get('source_ip')}")
        return "\n".join(lines)

    if any(word in text for word in ("top source", "most targeted", "top attacker", "attacker", "who is", "source ip")):
        top = context.get("top_sources", []) or []
        if not top:
            return "Not enough data yet to rank source hosts."
        lines = ["Top source hosts by alert activity:"]
        for ip, count in top[:5]:
            lines.append(f"- {ip} — {count} alert(s)")
        return "\n".join(lines)

    if any(word in text for word in ("protocol", "traffic", "packet count", "how many packets")):
        stats = context.get("stats", {})
        proto = stats.get("protocol_breakdown") or {}
        if not proto:
            return "No packet data has been recorded yet."
        lines = ["Protocol distribution:"]
        for name, count in sorted(proto.items(), key=lambda kv: kv[1], reverse=True):
            lines.append(f"- {name}: {count}")
        return "\n".join(lines)

    if "explain" in text or "mitigation" in text or "what should" in text:
        recent = context.get("recent_alerts", []) or []
        if not recent:
            return "I can explain any alert — but nothing has been logged yet. Try 'explain' after an alert appears."
        return explain_alert_text(recent[0]) + (
            "\n\nTip: use the Alerts page and select 'Explain' for any specific alert."
        )

    if any(word in text for word in ("anomaly", "scan", "machine learning", "outlier", "detect")):
        return (
            "Open the Analytics page and click 'Run AI Scan'. The Isolation Forest model scores recent packets "
            "against their learned baseline and flags statistical outliers with a confidence score."
        )

    if any(word in text for word in ("report", "export")):
        return "Use the Reports endpoints or the Export buttons on the Alerts page to download CSV or an HTML security report."

    if any(word in text for word in ("hello", "thanks", "thank", "bye", "goodbye", "sorry")):
        return "You're welcome — I'm here if you need the current security picture."

    return (
        "I didn't follow that. I keep my answers grounded in live SOC data. Try asking about the "
        "\"overview\", \"recent alerts\", \"high severity\", \"top sources\", \"protocols\", or ask me to "
        "\"explain\" the last alert."
    )


def _top_protocol(context: Dict[str, Any]) -> str:
    proto = (context.get("stats") or {}).get("protocol_breakdown") or {}
    if not proto:
        return "unknown"
    return max(proto, key=proto.get)


def _posture_label(context: Dict[str, Any]) -> str:
    high = sum(
        count
        for severity, count in ((context.get("stats") or {}).get("severity_breakdown") or {}).items()
        if str(severity).upper() in ("HIGH", "CRITICAL")
    )
    if high >= 5:
        return "CRITICAL"
    if high >= 1:
        return "ELEVATED"
    return "STABLE"


def _friendly_time(value: Any) -> str:
    try:
        timestamp = datetime.fromisoformat(str(value))
        return timestamp.strftime("%H:%M UTC")
    except (ValueError, TypeError):
        return str(value)


def assistant_respond(message: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Produce an assistant reply. Uses Groq when an API key is configured."""
    context = context or {}
    import os
    import json
    import urllib.request
    
    api_key = os.getenv("CYBERSHIELD_GEMINI_API_KEY")
    if api_key and message.strip():
        try:
            system_prompt = (
                "You are the assistant for the CyberShield AI mini-SOC. Answer concisely "
                "and ground every claim in the live SOC context provided. Context:\n"
                f"{context}"
            )
            
            payload = {
                "model": "gemini-2.5-flash",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message}
                ],
                "max_tokens": 1024,
                "temperature": 0.3
            }
            
            req = urllib.request.Request(
                "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                method="POST"
            )
            
            with urllib.request.urlopen(req, timeout=15) as response:
                result = json.loads(response.read().decode("utf-8"))
                reply = result["choices"][0]["message"]["content"]
                
                if reply:
                    return {"reply": reply, "provider": "gemini"}
        except Exception as exc:
            logger.warning("Gemini assistant unavailable (%s); using local mode.", exc)

    reply = _assistant_local(message, context)
    return {"reply": reply, "provider": "local"}


# ----------------------------------------------------------------------------
# Convenience: pull SOC context straight from the database
# ----------------------------------------------------------------------------


def build_soc_context(include_stats: bool = True) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        recent_alerts = (
            db.query(Alert).order_by(Alert.timestamp.desc()).limit(20).all()
        )
        context = {
            "recent_alerts": [
                {
                    "id": a.id,
                    "source_ip": a.source_ip,
                    "destination_ip": a.destination_ip,
                    "attack_type": a.attack_type,
                    "severity": a.severity,
                    "description": a.description,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                }
                for a in recent_alerts
            ]
        }
        if include_stats:
            from sqlalchemy import func

            severity_breakdown = {
                severity: count
                for severity, count in db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
            }
            protocol_breakdown = {
                protocol: count
                for protocol, count in db.query(Packet.protocol, func.count(Packet.id)).group_by(Packet.protocol).all()
            }
            context["stats"] = {
                "total_packets": db.query(Packet).count(),
                "total_alerts": db.query(Alert).count(),
                "severity_breakdown": severity_breakdown,
                "protocol_breakdown": protocol_breakdown,
            }
            top = (
                db.query(Alert.source_ip, func.count(Alert.id))
                .group_by(Alert.source_ip)
                .order_by(func.count(Alert.id).desc())
                .limit(5)
                .all()
            )
            context["top_sources"] = [[ip, count] for ip, count in top]
        return context
    finally:
        db.close()