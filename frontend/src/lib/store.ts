/**
 * Unified In-Memory & LocalStorage Forensic Investigation Store
 * Pre-seeds the platform with baseline investigations so the dashboard,
 * geolocation map, case list, and reports are immediately populated.
 */
import {
  InvestigationListItem,
  InvestigationDetail,
  DashboardStats,
  FullAnalysisResult,
  AnalystNote,
} from "./types";
import { DEMO_EMAILS } from "@/data/demo_emails";
import { analyzeEmail } from "./forensic-engine";

let serverStore: InvestigationDetail[] = [];

function initBaseline(): InvestigationDetail[] {
  const list: InvestigationDetail[] = [];
  for (const demo of DEMO_EMAILS) {
    const fixedId = `INV-DEMO-${demo.id.toUpperCase().replace(/[^A-Z0-9]/g, "-")}`;
    const analysis = analyzeEmail(demo.raw, `${demo.id}.eml`, fixedId);
    const item: InvestigationDetail = {
      id: fixedId,
      subject: analysis.summary.subject,
      sender: analysis.summary.sender,
      recipient: analysis.summary.recipient,
      email_date: analysis.summary.date,
      filename: `${demo.id}.eml`,
      threat_score: analysis.summary.overall_threat_score,
      severity: analysis.summary.threat_level as any,
      header_trust_score: analysis.summary.header_trust_score,
      source_ip: analysis.routing_hops[0]?.from_ip || "198.51.100.88",
      source_country: analysis.routing_hops[0]?.country || "United States",
      spf_status: analysis.authentication.spf.status,
      dkim_status: analysis.authentication.dkim.status,
      dmarc_status: analysis.authentication.dmarc.status,
      status: analysis.summary.overall_threat_score >= 80 ? "ESCALATED" : analysis.summary.overall_threat_score >= 40 ? "IN_PROGRESS" : "CLOSED",
      created_at: "2026-11-18T00:00:00.000Z",
      updated_at: new Date().toISOString(),
      summary: analysis.summary.verdict,
      raw_headers: analysis.raw.headers,
      analysis: analysis,
      notes: [
        {
          id: "note-1",
          author: "SOC Analyst",
          timestamp: "2026-11-18T00:05:00.000Z",
          content: `Initial forensic ingestion automated: Overall Threat Score ${analysis.summary.overall_threat_score}/100 (${analysis.summary.threat_level}).`,
        },
      ],
    };
    list.push(item);
  }
  return list;
}

function getStore(): InvestigationDetail[] {
  if (typeof window !== "undefined") {
    const cached = localStorage.getItem("sih26106_investigations");
    if (cached) {
      try {
        return JSON.parse(cached);
      } catch {
        // Fallback
      }
    }
    const fresh = initBaseline();
    localStorage.setItem("sih26106_investigations", JSON.stringify(fresh));
    return fresh;
  }

  if (serverStore.length === 0) {
    serverStore = initBaseline();
  }
  return serverStore;
}

function saveStore(items: InvestigationDetail[]) {
  if (typeof window !== "undefined") {
    localStorage.setItem("sih26106_investigations", JSON.stringify(items));
  } else {
    serverStore = items;
  }
}

export function getAllInvestigations(params?: {
  skip?: number;
  limit?: number;
  severity?: string;
  status?: string;
  search?: string;
}): { total: number; page: number; limit: number; items: InvestigationListItem[] } {
  let items = getStore();

  if (params?.severity) {
    items = items.filter((i) => i.severity.toLowerCase() === params.severity?.toLowerCase());
  }
  if (params?.status) {
    items = items.filter((i) => i.status.toLowerCase() === params.status?.toLowerCase());
  }
  if (params?.search) {
    const q = params.search.toLowerCase();
    items = items.filter(
      (i) =>
        i.subject.toLowerCase().includes(q) ||
        i.sender.toLowerCase().includes(q) ||
        i.id.toLowerCase().includes(q) ||
        i.source_ip.toLowerCase().includes(q)
    );
  }

  const total = items.length;
  const skip = params?.skip || 0;
  const limit = params?.limit || 50;
  const paginated = items.slice(skip, skip + limit);

  return {
    total,
    page: Math.floor(skip / limit) + 1,
    limit,
    items: paginated.map(({ analysis, raw_headers, ...rest }) => rest),
  };
}

export function getInvestigationById(id: string): InvestigationDetail | null {
  const items = getStore();
  const found = items.find((i) => i.id.toLowerCase() === id.toLowerCase());
  if (found) return found;

  // Fallback for demo IDs across serverless cold starts
  const matchDemo = DEMO_EMAILS.find(
    (d) =>
      `INV-DEMO-${d.id.toUpperCase().replace(/[^A-Z0-9]/g, "-")}`.toLowerCase() === id.toLowerCase() ||
      d.id.toLowerCase() === id.toLowerCase()
  );
  if (matchDemo) {
    const fixedId = `INV-DEMO-${matchDemo.id.toUpperCase().replace(/[^A-Z0-9]/g, "-")}`;
    const analysis = analyzeEmail(matchDemo.raw, `${matchDemo.id}.eml`, fixedId);
    return {
      id: fixedId,
      subject: analysis.summary.subject,
      sender: analysis.summary.sender,
      recipient: analysis.summary.recipient,
      email_date: analysis.summary.date,
      filename: `${matchDemo.id}.eml`,
      threat_score: analysis.summary.overall_threat_score,
      severity: analysis.summary.threat_level as any,
      header_trust_score: analysis.summary.header_trust_score,
      source_ip: analysis.routing_hops[0]?.from_ip || "198.51.100.88",
      source_country: analysis.routing_hops[0]?.country || "United States",
      spf_status: analysis.authentication.spf.status,
      dkim_status: analysis.authentication.dkim.status,
      dmarc_status: analysis.authentication.dmarc.status,
      status: "IN_PROGRESS",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      summary: analysis.summary.verdict,
      raw_headers: analysis.raw.headers,
      analysis,
      notes: [],
    };
  }
  return null;
}

export function saveNewInvestigation(analysis: FullAnalysisResult, filename: string = "email.eml"): InvestigationDetail {
  const items = getStore();
  const detail: InvestigationDetail = {
    id: analysis.summary.investigation_id,
    subject: analysis.summary.subject,
    sender: analysis.summary.sender,
    recipient: analysis.summary.recipient,
    email_date: analysis.summary.date,
    filename,
    threat_score: analysis.summary.overall_threat_score,
    severity: analysis.summary.threat_level as any,
    header_trust_score: analysis.summary.header_trust_score,
    source_ip: analysis.routing_hops[0]?.from_ip || "Unknown",
    source_country: analysis.routing_hops[0]?.country || "Unknown",
    spf_status: analysis.authentication.spf.status,
    dkim_status: analysis.authentication.dkim.status,
    dmarc_status: analysis.authentication.dmarc.status,
    status: "NEW",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    summary: analysis.summary.verdict,
    raw_headers: analysis.raw.headers,
    analysis,
    notes: [
      {
        id: `note-${Date.now()}`,
        author: "SOC Automated Ingestion",
        timestamp: new Date().toISOString(),
        content: `Ingested payload "${filename}". Threat score: ${analysis.summary.overall_threat_score}/100 (${analysis.summary.threat_level}).`,
      },
    ],
  };

  const updated = [detail, ...items.filter((i) => i.id !== detail.id)];
  saveStore(updated);
  return detail;
}

export function updateStatus(id: string, newStatus: string): boolean {
  const items = getStore();
  const target = items.find((i) => i.id === id);
  if (!target) return false;
  target.status = newStatus as any;
  target.updated_at = new Date().toISOString();
  saveStore([...items]);
  return true;
}

export function addNote(id: string, author: string, noteText: string): AnalystNote | null {
  const items = getStore();
  const target = items.find((i) => i.id === id);
  if (!target) return null;
  const note: AnalystNote = {
    id: `note-${Date.now()}`,
    author: author || "SOC Analyst",
    timestamp: new Date().toISOString(),
    content: noteText,
  };
  target.notes = [note, ...target.notes];
  target.updated_at = new Date().toISOString();
  saveStore([...items]);
  return note;
}

export function deleteById(id: string): boolean {
  const items = getStore();
  const filtered = items.filter((i) => i.id !== id);
  saveStore(filtered);
  return true;
}

export function getStats(): DashboardStats {
  const items = getStore();
  const total = items.length;
  const critical = items.filter((i) => i.severity === "CRITICAL").length;
  const high = items.filter((i) => i.severity === "HIGH").length;
  const threats = items.filter((i) => i.threat_score >= 40).length;
  const avg = total > 0 ? Math.round(items.reduce((acc, cur) => acc + cur.threat_score, 0) / total) : 0;

  const severityDist = [
    { name: "CRITICAL", count: critical, color: "#ef4444" },
    { name: "HIGH", count: high, color: "#f97316" },
    { name: "MEDIUM", count: items.filter((i) => i.severity === "MEDIUM").length, color: "#f59e0b" },
    { name: "LOW", count: items.filter((i) => i.severity === "LOW").length, color: "#3b82f6" },
    { name: "SAFE", count: items.filter((i) => i.severity === "SAFE").length, color: "#10b981" },
  ];

  const countryCounts: Record<string, number> = {};
  items.forEach((i) => {
    countryCounts[i.source_country] = (countryCounts[i.source_country] || 0) + 1;
  });
  const topCountries = Object.entries(countryCounts)
    .map(([country, count]) => ({ country, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  return {
    total_investigations: total,
    emails_analyzed: total,
    threats_detected: threats,
    critical_threats: critical,
    high_risk_emails: high,
    average_threat_score: avg,
    suspicious_urls: items.reduce((acc, cur) => acc + (cur.analysis?.urls?.filter((u) => u.risk >= 30).length || 0), 0),
    suspicious_attachments: items.reduce((acc, cur) => acc + (cur.analysis?.attachments?.filter((a) => a.suspicious).length || 0), 0),
    severity_distribution: severityDist,
    authentication_distribution: {
      spf: {
        pass: items.filter((i) => i.spf_status === "Pass").length,
        fail: items.filter((i) => i.spf_status === "Fail").length,
      },
      dkim: {
        pass: items.filter((i) => i.dkim_status === "Pass").length,
        fail: items.filter((i) => i.dkim_status === "Fail").length,
      },
      dmarc: {
        pass: items.filter((i) => i.dmarc_status === "Pass").length,
        fail: items.filter((i) => i.dmarc_status === "Fail").length,
      },
    },
    top_countries: topCountries,
    recent_investigations: items.slice(0, 5).map((i) => ({
      id: i.id,
      subject: i.subject,
      sender: i.sender,
      threat_score: i.threat_score,
      severity: i.severity,
      spf_status: i.spf_status,
      dkim_status: i.dkim_status,
      dmarc_status: i.dmarc_status,
      source_ip: i.source_ip,
      source_country: i.source_country,
      created_at: i.created_at,
      status: i.status,
    })),
  };
}

export function getGeoIntel() {
  const items = getStore();
  const points: any[] = [];
  items.forEach((i) => {
    if (i.analysis?.routing_hops) {
      i.analysis.routing_hops.forEach((h) => {
        if (h.latitude && h.longitude) {
          points.push({
            ip: h.from_ip,
            country: h.country,
            city: h.city,
            lat: h.latitude,
            lng: h.longitude,
            isp: h.isp,
            suspicious: h.suspicious,
          });
        }
      });
    }
  });

  return {
    total_locations: points.length,
    countries_count: new Set(points.map((p) => p.country)).size,
    geo_points: points,
  };
}
