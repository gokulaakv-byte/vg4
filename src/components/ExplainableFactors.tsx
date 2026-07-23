"use client";

import React, { useState } from "react";
import { ThreatFactor } from "@/lib/ai-analyzer";
import { ChevronDown, ChevronUp } from "lucide-react";

interface ExplainableFactorsProps {
  factors: ThreatFactor[];
}

export function ExplainableFactors({ factors }: ExplainableFactorsProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const getSeverityMeta = (severity: ThreatFactor["severity"]) => {
    switch (severity) {
      case "critical":
        return {
          labelColor: "text-[#ef5343] border-[#d9483b]/40",
          cardBorder: "border-[#282a31] hover:border-[#d9483b]/50 bg-[#16171c]",
          impactColor: "text-[#ef5343]",
        };
      case "high":
        return {
          labelColor: "text-[#f09a36] border-[#d98b2b]/40",
          cardBorder: "border-[#282a31] hover:border-[#d98b2b]/50 bg-[#16171c]",
          impactColor: "text-[#f09a36]",
        };
      case "medium":
      case "low":
        return {
          labelColor: "text-[#d8b068] border-[#8f8e89]/40",
          cardBorder: "border-[#282a31] hover:border-[#8f8e89]/50 bg-[#16171c]",
          impactColor: "text-[#d8b068]",
        };
      case "positive":
      default:
        return {
          labelColor: "text-[#48b882] border-[#389e6e]/40",
          cardBorder: "border-[#282a31] hover:border-[#389e6e]/50 bg-[#16171c]",
          impactColor: "text-[#48b882]",
        };
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between pb-2 border-b border-[#282a31]">
        <div>
          <h3 className="font-display text-base font-bold text-[#f0eee8] tracking-tight">
            Contributing Threat Signals
          </h3>
          <p className="text-xs text-[#8f8e89]">
            {factors.length} verifiable signals analyzed — plain-English evidence breakdown
          </p>
        </div>
      </div>

      <div className="space-y-3">
        {factors.map((factor) => {
          const meta = getSeverityMeta(factor.severity);
          const isExpanded = expandedId === factor.id;

          return (
            <div
              key={factor.id}
              className={`border rounded-lg p-4 transition-colors ${meta.cardBorder}`}
            >
              <div
                className="flex items-start justify-between gap-4 cursor-pointer select-none"
                onClick={() => toggleExpand(factor.id)}
              >
                <div className="space-y-1.5 flex-1">
                  <div className="flex items-center gap-3">
                    <span className="font-display font-bold text-sm text-[#f0eee8]">
                      {factor.title}
                    </span>
                    <span
                      className={`text-[10px] font-mono uppercase px-2 py-0.5 border rounded ${meta.labelColor}`}
                    >
                      {factor.severity}
                    </span>
                  </div>

                  <p className="text-xs text-[#b8b6b0] leading-relaxed font-sans">
                    {factor.explanation}
                  </p>
                </div>

                <div className="flex flex-col items-end shrink-0 pl-3">
                  <span className={`text-xs font-mono font-bold ${meta.impactColor}`}>
                    {factor.impactScore > 0 ? `+${factor.impactScore}` : factor.impactScore} pts
                  </span>
                  <button
                    type="button"
                    className="mt-2 text-[#8f8e89] hover:text-[#f0eee8] transition-colors p-1"
                    aria-label="Toggle technical proof"
                  >
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4" />
                    ) : (
                      <ChevronDown className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>

              {/* Technical proof collapsible section */}
              {isExpanded && (
                <div className="mt-3 pt-3 border-t border-[#282a31]">
                  <div className="text-[11px] font-mono text-[#8f8e89] bg-[#111215] p-3 rounded border border-[#22242b] break-all leading-relaxed">
                    <span className="text-[#6d6c67] block uppercase text-[10px] mb-1 font-sans font-semibold tracking-wider">
                      Technical Verification Log:
                    </span>
                    {factor.technicalEvidence}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
