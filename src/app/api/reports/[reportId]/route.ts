import { NextRequest, NextResponse } from "next/server";
import { db } from "@/db";
import { analysisReports } from "@/db/schema";
import { eq } from "drizzle-orm";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ reportId: string }> }
) {
  try {
    const { reportId } = await params;
    const reports = await db
      .select()
      .from(analysisReports)
      .where(eq(analysisReports.reportId, reportId))
      .limit(1);

    if (reports.length === 0) {
      return NextResponse.json({ error: "Report not found" }, { status: 404 });
    }

    return NextResponse.json({ report: reports[0] });
  } catch (error) {
    console.error("Fetch report error:", error);
    return NextResponse.json({ error: "Failed to fetch report" }, { status: 500 });
  }
}
