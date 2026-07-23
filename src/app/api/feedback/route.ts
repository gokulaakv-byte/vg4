import { NextRequest, NextResponse } from "next/server";
import { db } from "@/db";
import { userFeedback, analysisReports } from "@/db/schema";
import { eq, sql } from "drizzle-orm";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { reportId, feedbackType, feedbackReason } = body;

    if (!reportId || !feedbackType) {
      return NextResponse.json({ error: "Missing reportId or feedbackType" }, { status: 400 });
    }

    // Insert user feedback record
    await db.insert(userFeedback).values({
      reportId,
      feedbackType,
      feedbackReason: feedbackReason || null,
    });

    // Increment thumbs count on analysis report if exists
    if (feedbackType === "up") {
      await db
        .update(analysisReports)
        .set({ thumbsUp: sql`${analysisReports.thumbsUp} + 1` })
        .where(eq(analysisReports.reportId, reportId));
    } else if (feedbackType === "down") {
      await db
        .update(analysisReports)
        .set({ thumbsDown: sql`${analysisReports.thumbsDown} + 1` })
        .where(eq(analysisReports.reportId, reportId));
    }

    return NextResponse.json({ success: true, message: "Feedback recorded. Thank you!" });
  } catch (error) {
    console.error("Feedback submission error:", error);
    return NextResponse.json({ error: "Failed to record feedback" }, { status: 500 });
  }
}
