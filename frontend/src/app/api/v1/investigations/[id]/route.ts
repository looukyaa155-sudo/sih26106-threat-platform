import { NextRequest, NextResponse } from "next/server";
import { getInvestigationById, deleteById } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const item = getInvestigationById(params.id);
  if (!item) {
    return NextResponse.json({ success: false, error: { message: "Case not found" } }, { status: 404 });
  }
  return NextResponse.json({ success: true, data: item });
}

export async function DELETE(req: NextRequest, { params }: { params: { id: string } }) {
  deleteById(params.id);
  return NextResponse.json({ success: true });
}
