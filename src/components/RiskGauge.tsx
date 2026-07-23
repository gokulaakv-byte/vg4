"use client";

import React from "react";

interface RiskGaugeProps {
  score: number;
  level: "critical" | "caution" | "safe";
  size?: number;
}

export function RiskGauge({ score, level }: RiskGaugeProps) {
  let accentColor = "#389e6e"; // Safe Pine
  let accentBorder = "border-[#389e6e]/40";
  let accentBg = "bg-[#389e6e]/10";
  let accentText = "text-[#48b882]";
  let verdictLabel = "SAFE / LOW RISK";
  let verdictSub = "Standard communication profile";

  if (level === "critical" || score >= 70) {
    accentColor = "#d9483b"; // Threat Crimson
    accentBorder = "border-[#d9483b]/50";
    accentBg = "bg-[#d9483b]/10";
    accentText = "text-[#ef5343]";
    verdictLabel = "CRITICAL PHISHING THREAT";
    verdictSub = "Active threat indicators confirmed";
  } else if (level === "caution" || score >= 30) {
    accentColor = "#d98b2b"; // Ochre Amber
    accentBorder = "border-[#d98b2b]/50";
    accentBg = "bg-[#d98b2b]/10";
    accentText = "text-[#f09a36]";
    verdictLabel = "MODERATE CAUTION REQUIRED";
    verdictSub = "Unverified sender or domain anomalies";
  }

  // Generate 20 segmented spectrum bars for forensic signal meter
  const totalSegments = 20;
  const activeSegments = Math.round((score / 100) * totalSegments);

  return (
    <div className="w-full flex flex-col items-center justify-center p-6 bg-[#16171c] border border-[#282a31] rounded-xl">
      {/* Forensic Docket Header */}
      <div className="w-full flex items-center justify-between pb-3 border-b border-[#282a31] text-[11px] text-[#8f8e89] uppercase tracking-wider font-sans">
        <span>Forensic Risk Spectrum</span>
        <span className="font-mono">CALIB. 0–100</span>
      </div>

      {/* Large Forensic Score Readout */}
      <div className="my-5 flex items-baseline gap-2">
        <span className={`text-6xl font-display font-bold tracking-tight ${accentText}`}>
          {score}
        </span>
        <span className="text-sm font-mono text-[#8f8e89]">/100</span>
      </div>

      {/* Segmented Forensic Signal Meter */}
      <div className="w-full space-y-1.5">
        <div className="flex gap-1 h-3 w-full">
          {Array.from({ length: totalSegments }).map((_, idx) => {
            const isActive = idx < activeSegments;
            return (
              <div
                key={idx}
                className="flex-1 rounded-[1px] transition-all duration-300"
                style={{
                  backgroundColor: isActive ? accentColor : "#22242b",
                  opacity: isActive ? 1 : 0.4,
                }}
              />
            );
          })}
        </div>

        {/* Calibration Ticks */}
        <div className="flex justify-between text-[10px] font-mono text-[#8f8e89] pt-1">
          <span>00 (CLEAN)</span>
          <span>50 (CAUTION)</span>
          <span>100 (CRITICAL)</span>
        </div>
      </div>

      {/* Official Forensic Verdict Stamp */}
      <div className={`mt-5 w-full p-3 rounded-lg border ${accentBorder} ${accentBg} text-center`}>
        <div className={`text-xs font-bold uppercase tracking-wider ${accentText}`}>
          {verdictLabel}
        </div>
        <div className="text-[11px] text-[#8f8e89] mt-0.5 font-sans">
          {verdictSub}
        </div>
      </div>
    </div>
  );
}
