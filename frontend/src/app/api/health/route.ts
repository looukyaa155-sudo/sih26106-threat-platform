import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({
    status: "ACTIVE",
    version: "1.0.0",
    service: "Cyber Threat Intelligence Platform",
    components: {
      backend: "ACTIVE (Next.js Serverless & Async Pipeline)",
      database: "ACTIVE (Unified Session & Local Persistence)",
      nlp_engine: "ACTIVE (TF-IDF & Rule-Based Intent Classifier)",
      geolocation: "AVAILABLE (Interactive Map & Lat/Long Geotracer)",
      threat_intelligence: "ACTIVE (Threat Intel Provider Matrix)",
    },
  });
}
