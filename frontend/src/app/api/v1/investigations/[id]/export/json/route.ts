import { NextRequest, NextResponse } from "next/server";
import { getInvestigationById } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const item = getInvestigationById(params.id);
  if (!item) {
    return NextResponse.json({ success: false, error: { message: "Case not found" } }, { status: 404 });
  }

  const jsonStr = JSON.stringify(item, null, 2);
  return new NextResponse(jsonStr, {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Content-Disposition": `attachment; filename="${params.id}_forensic_dossier.json"`,
    },
  });
}
