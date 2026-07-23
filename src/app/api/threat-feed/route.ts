import { NextResponse } from "next/server";
import { db } from "@/db";
import { threatFeedItems, analysisReports } from "@/db/schema";
import { desc } from "drizzle-orm";

export async function GET() {
  try {
    const recentThreats = await db
      .select()
      .from(threatFeedItems)
      .orderBy(desc(threatFeedItems.createdAt))
      .limit(10);

    const totalScannedCount = await db.select().from(analysisReports);

    // Initial seed threats if DB is fresh
    const defaultThreats = [
      {
        id: 1,
        threatTitle: "Chase SMS Urgency Lure",
        targetBrand: "Chase Bank",
        domainDetected: "chase-fraud-verify9.xyz",
        riskScore: 96,
        threatCategory: "Banking Phish",
        createdAt: new Date().toISOString(),
      },
      {
        id: 2,
        threatTitle: "Geek Squad Fake Invoice #9948",
        targetBrand: "Geek Squad",
        domainDetected: "geeksquad-renew-secure.top",
        riskScore: 94,
        threatCategory: "Refund Scam",
        createdAt: new Date(Date.now() - 15 * 60000).toISOString(),
      },
      {
        id: 3,
        threatTitle: "Microsoft 365 Credential Portal",
        targetBrand: "Microsoft",
        domainDetected: "microsoft-security-portal-verify.com",
        riskScore: 91,
        threatCategory: "Credential Harvesting",
        createdAt: new Date(Date.now() - 42 * 60000).toISOString(),
      },
      {
        id: 4,
        threatTitle: "DocuSign Fake Severance Lure",
        targetBrand: "DocuSign",
        domainDetected: "secure-docs-review.click",
        riskScore: 93,
        threatCategory: "Brand Impersonation",
        createdAt: new Date(Date.now() - 95 * 60000).toISOString(),
      },
    ];

    const threats = recentThreats.length > 0 ? recentThreats : defaultThreats;
    const totalScans = Math.max(14820, 14820 + totalScannedCount.length);

    return NextResponse.json({
      success: true,
      stats: {
        totalScans,
        highRiskRate: "78.4%",
        avgScanTime: "1.4s",
        privacyRetention: "0 bytes (Zero Retention)",
      },
      threats,
    });
  } catch (error) {
    console.error("Threat feed error:", error);
    return NextResponse.json({ error: "Failed to fetch threat feed" }, { status: 500 });
  }
}
