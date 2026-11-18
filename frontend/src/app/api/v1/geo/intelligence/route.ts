import { NextResponse } from "next/server";
import { getGeoIntel } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET() {
  const data = getGeoIntel();
  return NextResponse.json(data);
}
