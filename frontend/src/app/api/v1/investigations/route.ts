import { NextRequest, NextResponse } from "next/server";
import { getAllInvestigations } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const skip = parseInt(searchParams.get("skip") || "0", 10);
  const limit = parseInt(searchParams.get("limit") || "50", 10);
  const severity = searchParams.get("severity") || undefined;
  const status = searchParams.get("status") || undefined;
  const search = searchParams.get("search") || undefined;

  const data = getAllInvestigations({ skip, limit, severity, status, search });
  return NextResponse.json(data);
}
