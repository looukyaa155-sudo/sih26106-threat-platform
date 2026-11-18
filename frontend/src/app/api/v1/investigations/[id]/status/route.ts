import { NextRequest, NextResponse } from "next/server";
import { updateStatus } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const body = await req.json();
    const success = updateStatus(params.id, body.status);
    if (!success) {
      return NextResponse.json({ success: false, error: { message: "Case not found" } }, { status: 404 });
    }
    return NextResponse.json({ success: true });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: { message: err.message } }, { status: 500 });
  }
}
