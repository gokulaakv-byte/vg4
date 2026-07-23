import { NextRequest, NextResponse } from "next/server";
import { analyzeMessageContent } from "@/lib/ai-analyzer";
import { parseScreenshotOcr } from "@/lib/ocr-parser";
import { db } from "@/db";
import { analysisReports, threatFeedItems } from "@/db/schema";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { text, screenshotBase64, inputType = "text" } = body;

    let contentToAnalyze = (text || "").trim();

    if (inputType === "screenshot" && screenshotBase64) {
      const ocr = parseScreenshotOcr(screenshotBase64);
      if (ocr.extractedText) {
        contentToAnalyze = ocr.extractedText;
      }
    }

    if (!contentToAnalyze) {
      return NextResponse.json(
        { error: "Please enter text, paste an email/SMS, or upload a screenshot to analyze." },
        { status: 400 }
      );
    }

    // Perform full AI analysis & live threat intel lookup
    const result = await analyzeMessageContent(contentToAnalyze, inputType);

    // Save sanitized report metadata in DB (Zero raw text stored, complying with PRD privacy rule)
    try {
      await db.insert(analysisReports).values({
        reportId: result.reportId,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        senderDisplay: result.senderDisplay || null,
        senderDomain: result.senderDomain || null,
        targetBrand: result.targetBrand || null,
        extractedDomains: result.extractedDomains,
        extractedUrls: result.extractedUrls,
        threatFactors: result.threatFactors,
        aiSummary: result.aiSummary,
        likelyObjective: result.likelyObjective,
        recommendationAction: result.recommendationAction,
        recommendationText: result.recommendationText,
        inputType: result.inputType,
        processingTimeMs: result.processingTimeMs,
      });

      // If high risk, add to community threat feed
      if (result.riskScore >= 70 && result.extractedDomains.length > 0) {
        await db.insert(threatFeedItems).values({
          threatTitle: `${result.targetBrand || "Credential Phish"} Campaign`,
          targetBrand: result.targetBrand || "Unknown Organization",
          domainDetected: result.extractedDomains[0],
          riskScore: result.riskScore,
          threatCategory: "High-Risk Phishing",
        });
      }
    } catch (dbErr) {
      console.error("DB persistence error (non-fatal):", dbErr);
    }

    return NextResponse.json({
      success: true,
      analysis: result,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Failed to analyze message";
    console.error("Analysis route error:", error);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
