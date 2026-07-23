"use client";

import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Lock,
  Globe,
  Share2,
  RefreshCw,
  Info,
} from "lucide-react";
import { RiskGauge } from "@/components/RiskGauge";
import { ExplainableFactors } from "@/components/ExplainableFactors";
import { WhoisPanel } from "@/components/WhoisPanel";
import { ExportReportModal } from "@/components/ExportReportModal";
import { FeedbackWidget } from "@/components/FeedbackWidget";
import { DomainLookupModal } from "@/components/DomainLookupModal";
import { AnalysisResult } from "@/lib/ai-analyzer";

export default function VigilPhishHome() {
  const [inputText, setInputText] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisStep, setAnalysisStep] = useState(0);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [isDomainLookupOpen, setIsDomainLookupOpen] = useState(false);

  // Forensic analysis step cycle
  const steps = [
    "Extracting embedded URLs, sender headers & brand entities...",
    "Querying live RDAP / WHOIS domain age registry...",
    "Checking VirusTotal & PhishTank multi-engine databases...",
    "Evaluating psychological urgency & coercive triggers...",
    "Synthesizing 0–100 explainable threat docket...",
  ];

  const handleAnalyze = async () => {
    if (!inputText.trim()) {
      setErrorMsg("Please paste a suspicious email, text message, or communication header to analyze.");
      return;
    }

    setErrorMsg(null);
    setIsAnalyzing(true);
    setAnalysisStep(0);

    const stepInterval = setInterval(() => {
      setAnalysisStep((prev) => (prev < steps.length - 1 ? prev + 1 : prev));
    }, 450);

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: inputText.trim(),
          inputType: "text",
        }),
      });

      clearInterval(stepInterval);

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Analysis failed");
      }

      const data = await res.json();
      setResult(data.analysis);

      setTimeout(() => {
        const el = document.getElementById("analysis-result-section");
        if (el) el.scrollIntoView({ behavior: "smooth" });
      }, 100);
    } catch (err: unknown) {
      clearInterval(stepInterval);
      const msg = err instanceof Error ? err.message : "Analysis failed";
      setErrorMsg(msg);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#121317] text-[#f0eee8] flex flex-col selection:bg-[#343740] selection:text-[#f0eee8]">
      {/* Editorial Header */}
      <header className="sticky top-0 z-40 bg-[#121317]/95 backdrop-blur border-b border-[#282a31]">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="font-display font-bold text-lg tracking-tight text-[#f0eee8]">
              VIGILPHISH
            </span>
            <span className="text-[11px] font-mono text-[#8f8e89] border-l border-[#282a31] pl-3 hidden sm:inline">
              Evidence-Based Threat Intelligence
            </span>
          </div>

          <div className="flex items-center gap-4 text-xs">
            <div className="hidden md:flex items-center gap-1.5 text-[#8f8e89]">
              <Lock className="w-3.5 h-3.5 text-[#8f8e89]" />
              <span>Zero Message Storage</span>
            </div>

            <button
              onClick={() => setIsDomainLookupOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#1b1d22] hover:bg-[#282a31] border border-[#282a31] text-xs text-[#f0eee8] transition-colors font-sans"
            >
              <Globe className="w-3.5 h-3.5 text-[#8f8e89]" />
              <span>WHOIS Query</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Forensic Evidence Canvas */}
      <main className="flex-1 max-w-5xl w-full mx-auto px-6 py-16 space-y-16">
        {/* Calm, High-Impact Hero Section */}
        <div className="max-w-2xl space-y-4">
          <p className="text-xs font-mono text-[#8f8e89] uppercase tracking-widest">
            Investigative Threat Assessment
          </p>
          <h1 className="text-3xl sm:text-4xl font-display font-bold text-[#f0eee8] tracking-tight leading-snug">
            Analyze suspicious messages against live domain intelligence.
          </h1>
          <p className="text-sm sm:text-base text-[#8f8e89] leading-relaxed font-sans">
            Paste any email headers, SMS notification, or payment lure. VigilPhish evaluates domain registration age, multi-engine security blacklists, and coercive language to deliver an explainable risk dossier.
          </p>
        </div>

        {/* Scanner Input Station */}
        <div className="bg-[#1b1d22] border border-[#282a31] rounded-xl shadow-lg overflow-hidden">
          <div className="flex items-center justify-between border-b border-[#282a31] bg-[#16171c] px-6 py-3.5 text-xs text-[#8f8e89]">
            <div className="flex items-center gap-2 font-medium text-[#f0eee8]">
              <FileText className="w-4 h-4 text-[#8f8e89]" />
              <span>Message Evidence Input</span>
            </div>
            <span className="font-mono text-[11px]">TXT / UTF-8</span>
          </div>

          <div className="p-6 space-y-5">
            <div className="relative">
              <textarea
                rows={7}
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Paste the suspicious email text, headers, or SMS alert here... (e.g. 'CHASE ALERT: Unauthorized charge of $1,489.99. Verify at https://chase-fraud-verify9.xyz/auth')"
                className="w-full bg-[#111215] border border-[#282a31] rounded-lg p-4 text-xs sm:text-sm text-[#f0eee8] placeholder:text-[#6d6c67] focus:outline-none focus:border-[#8f8e89] font-mono leading-relaxed transition-colors"
              />
              <div className="absolute bottom-3 right-3 text-[11px] font-mono text-[#6d6c67]">
                {inputText.length} chars
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-4 pt-1">
              <span className="text-xs text-[#8f8e89] font-sans">
                Privacy policy: Submitted message content is discarded immediately after scan.
              </span>

              <div className="flex items-center gap-3">
                {inputText && (
                  <button
                    onClick={() => setInputText("")}
                    className="px-3 py-2 text-xs text-[#8f8e89] hover:text-[#f0eee8] transition-colors"
                  >
                    Clear
                  </button>
                )}
                <button
                  onClick={handleAnalyze}
                  disabled={isAnalyzing}
                  className="bg-[#282a31] hover:bg-[#343740] text-[#f0eee8] font-medium px-5 py-2.5 rounded-lg text-xs sm:text-sm flex items-center gap-2 border border-[#3b3e49] transition-colors disabled:opacity-50"
                >
                  {isAnalyzing ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-[#8f8e89]" />
                      <span>Scanning Evidence...</span>
                    </>
                  ) : (
                    <span>Examine Phishing Risk</span>
                  )}
                </button>
              </div>
            </div>

            {errorMsg && (
              <div className="p-3 rounded bg-[#d9483b]/10 border border-[#d9483b]/30 text-[#ef5343] text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}
          </div>
        </div>

        {/* Live Diagnostic Indicator when Analyzing */}
        {isAnalyzing && (
          <div className="bg-[#1b1d22] border border-[#282a31] rounded-xl p-8 text-center space-y-3">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto text-[#8f8e89]" />
            <h3 className="font-display font-bold text-base text-[#f0eee8]">
              Executing Forensic Examination
            </h3>
            <p className="text-xs font-mono text-[#8f8e89]">
              {steps[analysisStep]}
            </p>
          </div>
        )}

        {/* Forensic Results Dossier Section */}
        {result && !isAnalyzing && (
          <div id="analysis-result-section" className="space-y-8 pt-4">
            <div className="bg-[#1b1d22] border border-[#282a31] rounded-xl p-6 sm:p-8 space-y-8 shadow-xl">
              {/* Header Bar */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-6 border-b border-[#282a31]">
                <div>
                  <div className="text-[11px] font-mono text-[#8f8e89] mb-1">
                    REPORT REFERENCE: {result.reportId}
                  </div>
                  <h2 className="text-xl sm:text-2xl font-display font-bold text-[#f0eee8] tracking-tight">
                    {result.riskLevel === "critical"
                      ? "Critical Threat Confirmed"
                      : result.riskLevel === "caution"
                      ? "Suspicious Elements Present"
                      : "Verified Low Risk"}
                  </h2>
                </div>

                <button
                  onClick={() => setIsExportModalOpen(true)}
                  className="bg-[#16171c] hover:bg-[#282a31] text-[#f0eee8] text-xs font-medium px-4 py-2 rounded-lg border border-[#282a31] flex items-center gap-2 transition-colors"
                >
                  <Share2 className="w-3.5 h-3.5 text-[#8f8e89]" />
                  <span>Export Dossier</span>
                </button>
              </div>

              {/* Grid: Signature Forensic Risk Gauge + Executive Prose */}
              <div className="grid grid-cols-1 md:grid-cols-12 gap-8 items-start">
                <div className="md:col-span-5">
                  <RiskGauge score={result.riskScore} level={result.riskLevel} />
                </div>

                <div className="md:col-span-7 space-y-5">
                  <div>
                    <span className="text-[11px] font-mono uppercase tracking-wider text-[#8f8e89] block mb-1.5">
                      Executive Summary
                    </span>
                    <p className="text-sm sm:text-base text-[#f0eee8] leading-relaxed font-sans">
                      {result.aiSummary}
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-[#16171c] border border-[#282a31] text-xs space-y-1">
                    <span className="text-[#8f8e89] font-mono uppercase text-[10px] block">
                      Probable Attacker Objective:
                    </span>
                    <span className="text-[#f0eee8] font-medium font-sans">
                      {result.likelyObjective}
                    </span>
                  </div>

                  {/* High-Impact Recommendation Directive */}
                  <div
                    className={`p-4 rounded-lg border text-xs sm:text-sm font-medium flex items-center gap-3 ${
                      result.riskLevel === "critical"
                        ? "bg-[#d9483b]/10 border-[#d9483b]/40 text-[#ef5343]"
                        : result.riskLevel === "caution"
                        ? "bg-[#d98b2b]/10 border-[#d98b2b]/40 text-[#f09a36]"
                        : "bg-[#389e6e]/10 border-[#389e6e]/40 text-[#48b882]"
                    }`}
                  >
                    {result.riskLevel === "critical" ? (
                      <ShieldAlert className="w-5 h-5 shrink-0" />
                    ) : (
                      <ShieldCheck className="w-5 h-5 shrink-0" />
                    )}
                    <span>{result.recommendationAction}</span>
                  </div>
                </div>
              </div>

              {/* Explainable Threat Factors Section */}
              <div className="pt-6 border-t border-[#282a31]">
                <ExplainableFactors factors={result.threatFactors} />
              </div>

              {/* Live Threat Intelligence Feeds */}
              <div className="pt-6 border-t border-[#282a31] space-y-4">
                <h3 className="font-display font-bold text-base text-[#f0eee8]">
                  Domain & Blacklist Verification Ledger
                </h3>
                <WhoisPanel
                  whois={result.whoisData}
                  virusTotal={result.virusTotalData}
                  extractedDomains={result.extractedDomains}
                />
              </div>

              {/* Actionable Incident Protocol */}
              <div className="pt-6 border-t border-[#282a31] space-y-3">
                <div className="flex items-center gap-2 text-xs font-mono text-[#8f8e89] uppercase tracking-wider">
                  <Info className="w-3.5 h-3.5" />
                  <span>Recommended Safety Protocol</span>
                </div>
                <div className="bg-[#16171c] border border-[#282a31] rounded-lg p-4 text-xs sm:text-sm text-[#b8b6b0] whitespace-pre-line leading-relaxed font-sans">
                  {result.recommendationText}
                </div>
              </div>

              {/* Accuracy Feedback Widget */}
              <div className="pt-6 border-t border-[#282a31]">
                <FeedbackWidget reportId={result.reportId} />
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Editorial Footer */}
      <footer className="border-t border-[#282a31] bg-[#16171c] py-8 text-xs text-[#8f8e89] mt-auto">
        <div className="max-w-6xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="font-display font-bold text-[#f0eee8]">VIGILPHISH</span>
            <span>— Consumer Phishing Risk Intelligence</span>
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono">
            <span>Zero Data Retention</span>
            <span>•</span>
            <span>Live RDAP & Threat Feeds</span>
          </div>
        </div>
      </footer>

      {/* Export Modal */}
      {result && (
        <ExportReportModal
          analysis={result}
          isOpen={isExportModalOpen}
          onClose={() => setIsExportModalOpen(false)}
        />
      )}

      {/* Standalone Domain Lookup Modal */}
      <DomainLookupModal
        isOpen={isDomainLookupOpen}
        onClose={() => setIsDomainLookupOpen(false)}
      />
    </div>
  );
}
