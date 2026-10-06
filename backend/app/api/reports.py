"""Security report generation — dependency-free (Python standard library only)."""

import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert, Packet

router = APIRouter(tags=["reports"])


def _ordered_alerts(db: Session, limit: int = 500):
    return (
        db.query(Alert)
        .order_by(Alert.timestamp.desc())
        .limit(limit)
        .all()
    )


def _ordered_packets(db: Session, limit: int = 500):
    return (
        db.query(Packet)
        .order_by(Packet.timestamp.desc())
        .limit(limit)
        .all()
    )


@router.get("/summary")
def report_summary(db: Session = Depends(get_db)):
    total_packets = db.query(Packet).count()
    total_alerts = db.query(Alert).count()

    severity_breakdown = {}
    for severity, count in db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all():
        severity_breakdown[severity] = count

    protocol_breakdown = {}
    for protocol, count in db.query(Packet.protocol, func.count(Packet.id)).group_by(Packet.protocol).all():
        protocol_breakdown[protocol] = count

    top_sources = (
        db.query(Alert.source_ip, func.count(Alert.id))
        .group_by(Alert.source_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
        .all()
    )

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "severity_breakdown": severity_breakdown,
        "protocol_breakdown": protocol_breakdown,
        "top_source_ips": [{"source_ip": ip, "count": count} for ip, count in top_sources],
    }


def _csv_response(rows: list[list], columns: list[str], filename: str) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    writer.writerows(rows)
    payload = buffer.getvalue()
    return PlainTextResponse(
        content=payload,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "text/csv",
        },
    )


@router.get("/csv/alerts")
def alerts_csv(limit: int = 1000, db: Session = Depends(get_db)):
    rows = [
        [
            alert.id,
            alert.source_ip,
            alert.destination_ip,
            alert.attack_type,
            alert.severity,
            alert.description or "",
            alert.timestamp.strftime("%Y-%m-%d %H:%M:%S") if alert.timestamp else "",
        ]
        for alert in _ordered_alerts(db, limit)
    ]
    return _csv_response(
        rows,
        ["id", "source_ip", "destination_ip", "attack_type", "severity", "description", "timestamp"],
        f"alerts_{datetime.utcnow().strftime('%Y%m%d')}.csv",
    )


@router.get("/csv/packets")
def packets_csv(limit: int = 1000, db: Session = Depends(get_db)):
    rows = [
        [
            packet.id,
            packet.source_ip,
            packet.destination_ip,
            packet.protocol,
            packet.source_port or "",
            packet.destination_port or "",
            packet.packet_length,
            packet.timestamp.strftime("%Y-%m-%d %H:%M:%S") if packet.timestamp else "",
        ]
        for packet in _ordered_packets(db, limit)
    ]
    return _csv_response(
        rows,
        ["id", "source_ip", "destination_ip", "protocol", "source_port", "destination_port", "packet_length", "timestamp"],
        f"packets_{datetime.utcnow().strftime('%Y%m%d')}.csv",
    )


@router.get("/html", response_class=HTMLResponse)
def html_report(limit: int = 50, db: Session = Depends(get_db)):
    """A self-contained, printable HTML security report."""
    summary = report_summary(db=db)
    alerts = _ordered_alerts(db, limit)

    severity_legend = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_rows_html = "".join(
        f"<tr><td>{severity}</td><td>{summary['severity_breakdown'].get(severity, 0)}</td></tr>"
        for severity in severity_legend
    )
    protocol_rows_html = "".join(
        f"<tr><td>{name}</td><td>{count}</td></tr>"
        for name, count in summary["protocol_breakdown"].items()
    )
    top_sources_html = "".join(
        f"<li><code>{item['source_ip']}</code> — {item['count']} alert(s)</li>"
        for item in summary["top_source_ips"]
    ) or "<li>No data yet.</li>"

    alert_rows_html = "".join(
        f"<tr>"
        f"<td>{alert.id}</td>"
        f"<td>{alert.severity}</td>"
        f"<td>{alert.attack_type}</td>"
        f"<td>{alert.source_ip}</td>"
        f"<td>{alert.destination_ip}</td>"
        f"<td>{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S') if alert.timestamp else '—'}</td>"
        f"</tr>"
        for alert in alerts
    ) or "<tr><td colspan='6' class='muted'>No alerts recorded.</td></tr>"

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>CyberShield AI — Security Report</title>
<style>
  body {{ font-family: -apple-system, 'Segoe UI', system-ui, sans-serif; color: #0f172a; margin: 0; padding: 40px 48px; background: #f8fafc; }}
  h1 {{ font-size: 26px; margin: 0 0 4px; }}
  h2 {{ font-size: 17px; margin: 0 0 12px; border-bottom: 2px solid #3b82f6; padding-bottom: 6px; }}
  .report-header {{ display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; }}
  .meta {{ color: #64748b; font-size: 13px; }}
  .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 24px; margin-top: 24px; }}
  section {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #eef2f7; font-size: 13px; }}
  th {{ color: #3b82f6; text-transform: uppercase; font-size: 11px; letter-spacing: .05em; }}
  .stats {{ display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 16px; margin-top: 24px; }}
  .stat {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px; }}
  .stat strong {{ display: block; font-size: 28px; color: #1d4ed8; }}
  .stat span {{ color: #64748b; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }}
  .muted {{ color: #94a3b8; }}
  ul {{ padding-left: 20px; }}
  li {{ font-size: 13px; margin: 4px 0; }}
  @media print {{ body {{ padding: 0; }} section, .stat {{ break-inside: avoid; }} }}
  @media (max-width: 760px) {{ .stats, .grid {{ grid-template-columns: 1fr; }} }}
</style></head>
<body>
  <div class="report-header">
    <div><h1>🛡️ CyberShield AI — Security Report</h1><p class="meta">Mini SOC · Defensive monitoring report</p></div>
    <div class="meta">Generated: {generated_at}</div>
  </div>

  <div class="stats">
    <div class="stat"><strong>{summary['total_packets']}</strong><span>Packets</span></div>
    <div class="stat"><strong>{summary['total_alerts']}</strong><span>Alerts</span></div>
    <div class="stat"><strong>{len(summary['top_source_ips'])}</strong><span>Top sources</span></div>
    <div class="stat"><strong>{len(summary['protocol_breakdown'])}</strong><span>Protocols</span></div>
  </div>

  <div class="grid">
    <section>
      <h2>Alerts by Severity</h2>
      <table><thead><tr><th>Severity</th><th>Count</th></tr></thead>
      <tbody>{severity_rows_html}</tbody></table>
    </section>
    <section>
      <h2>Protocol Distribution</h2>
      <table><thead><tr><th>Protocol</th><th>Count</th></tr></thead>
      <tbody>{protocol_rows_html}</tbody></table>
    </section>
  </div>

  <section style="margin-top: 24px;">
    <h2>Top Source Hosts</h2>
    <ul>{top_sources_html}</ul>
  </section>

  <section style="margin-top: 24px;">
    <h2>Recent Alerts</h2>
    <div style="overflow-x:auto;">
    <table><thead><tr><th>ID</th><th>Severity</th><th>Type</th><th>Source</th><th>Destination</th><th>Time</th></tr></thead>
    <tbody>{alert_rows_html}</tbody></table>
    </div>
  </section>
</body></html>"""

    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'attachment; filename="cybershield_report_{datetime.utcnow().strftime("%Y%m%d")}.html"'
        },
    )