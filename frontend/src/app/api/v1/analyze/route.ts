import { NextRequest, NextResponse } from "next/server";
import { analyzeEmail } from "@/lib/forensic-engine";
import { saveNewInvestigation } from "@/lib/store";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const formData = await req.formData();
    const file = formData.get("file") as File | null;
    const rawText = formData.get("raw_text") as string | null;

    let content = "";
    let filename = "email.eml";

    if (file) {
      filename = file.name;
      content = await file.text();
    } else if (rawText) {
      content = rawText;
    }

    if (!content.trim()) {
      return NextResponse.json(
        { success: false, error: { message: "No email payload or raw text provided." } },
        { status: 400 }
      );
    }

    const result = analyzeEmail(content, filename);
    saveNewInvestigation(result, filename);

    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      { success: false, error: { message: err.message || "Failed to analyze email payload." } },
      { status: 500 }
    );
  }
}
