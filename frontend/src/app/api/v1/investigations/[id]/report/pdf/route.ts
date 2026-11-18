import { NextRequest, NextResponse } from "next/server";
import { getInvestigationById } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const item = getInvestigationById(params.id);
  if (!item) {
    return NextResponse.json({ success: false, error: { message: "Case not found" } }, { status: 404 });
  }

  const analysis = item.analysis;
  const sevColor =
    item.severity === "CRITICAL"
      ? "#ef4444"
      : item.severity === "HIGH"
      ? "#f97316"
      : item.severity === "MEDIUM"
      ? "#f59e0b"
      : "#10b981";

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Forensic Dossier - ${item.id}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #fff; color: #1e293b; padding: 40px; line-height: 1.5; font-size: 13px; }
    .header { border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-start; }
    .title { font-size: 20px; font-weight: 800; color: #0f172a; text-transform: uppercase; letter-spacing: 0.5px; }
    .subtitle { font-size: 11px; color: #64748b; margin-top: 4px; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 12px; color: #fff; background: ${sevColor}; }
    .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 24px; }
    .card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; }
    .card-title { font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase; margin-bottom: 8px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }
    .field { margin-bottom: 6px; font-size: 12px; }
    .field span { color: #64748b; font-weight: 600; display: inline-block; width: 120px; }
    .threat-banner { background: #f1f5f9; border-left: 4px solid ${sevColor}; padding: 12px 16px; margin-bottom: 24px; border-radius: 0 8px 8px 0; }
    .threat-score { font-size: 24px; font-weight: 800; color: ${sevColor}; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 11px; }
    th { text-align: left; background: #f1f5f9; padding: 8px; border: 1px solid #e2e8f0; color: #475569; }
    td { padding: 8px; border: 1px solid #e2e8f0; }
    .print-bar { position: fixed; bottom: 20px; right: 20px; background: #0f172a; padding: 10px 20px; border-radius: 30px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); }
    .print-btn { background: #3b82f6; color: #fff; border: none; padding: 8px 16px; border-radius: 20px; font-weight: 600; font-size: 12px; cursor: pointer; }
    @media print {
      .print-bar { display: none; }
      body { padding: 0; }
    }
  </style>
</head>
<body>
  <div class="print-bar">
    <button class="print-btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
  </div>

  <div class="header">
    <div>
      <div class="title">SIH26106 Digital Forensics Intelligence Dossier</div>
      <div class="subtitle">AICTE Cyber Threat Intelligence & Analysis Gateway | Case ID: ${item.id}</div>
    </div>
    <div style="text-align: right;">
      <span class="badge">${item.severity}</span>
      <div style="font-size: 10px; color: #64748b; margin-top: 4px;">Status: ${item.status}</div>
    </div>
  </div>

  <div class="threat-banner">
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <div>
        <div style="font-size: 11px; font-weight: 700; color: #475569; text-transform: uppercase;">Overall Forensic Threat Score</div>
        <div style="font-size: 12px; color: #334155; margin-top: 2px;">${item.summary}</div>
      </div>
      <div class="threat-score">${item.threat_score} / 100</div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-title">1. Transmission & Header Metadata</div>
      <div class="field"><span>Subject:</span> <b>${item.subject}</b></div>
      <div class="field"><span>Sender (From):</span> ${item.sender}</div>
      <div class="field"><span>Recipient (To):</span> ${item.recipient}</div>
      <div class="field"><span>Date Asserted:</span> ${item.email_date}</div>
      <div class="field"><span>Origin Relay:</span> ${item.source_ip} (${item.source_country})</div>
    </div>

    <div class="card">
      <div class="card-title">2. Authentication Protocols & Trust</div>
      <div class="field"><span>Header Trust:</span> <b>${item.header_trust_score} / 100</b></div>
      <div class="field"><span>SPF Result:</span> ${item.spf_status}</div>
      <div class="field"><span>DKIM Result:</span> ${item.dkim_status}</div>
      <div class="field"><span>DMARC Result:</span> ${item.dmarc_status}</div>
      <div class="field"><span>From vs Reply-To:</span> ${analysis?.sender_analysis?.from_reply_to_mismatch ? "MISMATCH DETECTED" : "ALIGNED"}</div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 24px;">
    <div class="card-title">3. Factor Point Attribution & Forensic Evidence (${analysis?.threat_factors?.length || 0} Factors)</div>
    <table>
      <thead>
        <tr>
          <th>Category</th>
          <th>Forensic Indicator</th>
          <th>Points</th>
          <th>Observed Evidence</th>
        </tr>
      </thead>
      <tbody>
        ${(analysis?.threat_factors || [])
          .map(
            (f) => `<tr>
          <td><b>${f.category}</b></td>
          <td>${f.factor}</td>
          <td style="color: #ef4444; font-weight: 700;">+${f.points}</td>
          <td>${f.evidence || f.description}</td>
        </tr>`
          )
          .join("")}
      </tbody>
    </table>
  </div>

  <div class="card" style="margin-bottom: 24px;">
    <div class="card-title">4. Chronological Network Routing Trajectory (${analysis?.routing_hops?.length || 0} Hops)</div>
    <table>
      <thead>
        <tr>
          <th>Hop</th>
          <th>Host IP</th>
          <th>Location</th>
          <th>ISP / AS Organization</th>
          <th>Classification</th>
        </tr>
      </thead>
      <tbody>
        ${(analysis?.routing_hops || [])
          .map(
            (h) => `<tr>
          <td><b>Hop #${h.hop_number}</b></td>
          <td>${h.from_ip}</td>
          <td>${h.city}, ${h.country}</td>
          <td>${h.isp} (${h.asn})</td>
          <td>${h.ip_classification}</td>
        </tr>`
          )
          .join("")}
      </tbody>
    </table>
  </div>

  <div class="card">
    <div class="card-title">5. Chain of Custody & Analyst Triage Trail</div>
    <div style="font-size: 11px; color: #475569; line-height: 1.6;">
      ${(item.notes || [])
        .map(
          (n) => `<div style="margin-bottom: 6px;">
        <b>${n.timestamp.slice(0, 19).replace("T", " ")}</b> [${n.author}]: ${n.content}
      </div>`
        )
        .join("")}
    </div>
  </div>

  <div style="margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 10px; font-size: 10px; color: #94a3b8; display: flex; justify-content: space-between;">
    <span>SIH26106 SOC Intelligence Engine</span>
    <span>Generated: ${new Date().toUTCString()}</span>
    <span>Page 1 of 1</span>
  </div>
</body>
</html>`;

  return new NextResponse(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
    },
  });
}
