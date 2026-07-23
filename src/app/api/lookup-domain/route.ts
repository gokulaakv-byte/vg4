import { NextRequest, NextResponse } from "next/server";
import { getWhoisIntel, getThreatFeedReputation } from "@/lib/threat-intel";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const domain = searchParams.get("domain");

    if (!domain) {
      return NextResponse.json({ error: "Domain parameter is required" }, { status: 400 });
    }

    const clean = domain.replace(/^https?:\/\//i, "").split("/")[0];
    const [whois, virusTotal] = await Promise.all([
      getWhoisIntel(clean),
      getThreatFeedReputation(clean),
    ]);

    return NextResponse.json({
      domain: clean,
      whois,
      virusTotal,
    });
  } catch (error) {
    console.error("Domain lookup error:", error);
    return NextResponse.json({ error: "Failed to lookup domain" }, { status: 500 });
  }
}
