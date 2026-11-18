import { NextRequest, NextResponse } from "next/server";
import { addNote } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const body = await req.json();
    const note = addNote(params.id, body.author, body.note);
    if (!note) {
      return NextResponse.json({ success: false, error: { message: "Case not found" } }, { status: 404 });
    }
    return NextResponse.json(note);
  } catch (err: any) {
    return NextResponse.json({ success: false, error: { message: err.message } }, { status: 500 });
  }
}
