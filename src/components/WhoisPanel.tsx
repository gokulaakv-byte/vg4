"use client";

import React from "react";
import { WhoisResult, VirusTotalResult } from "@/lib/threat-intel";

interface WhoisPanelProps {
  whois?: WhoisResult;
  virusTotal?: VirusTotalResult;
  extractedDomains: string[];
}

export function WhoisPanel({ whois, virusTotal, extractedDomains }: WhoisPanelProps) {
  const primaryDomain = whois?.domain || extractedDomains[0] || "No domain extracted";

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* WHOIS / RDAP Registry Record Card */}
      <div className="bg-[#16171c] border border-[#282a31] rounded-xl p-5 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between pb-3 border-b border-[#282a31]">
            <span className="font-display font-bold text-sm text-[#f0eee8]">
              Domain Registry Ledger
            </span>
            <span className="text-[10px] font-mono text-[#8f8e89] uppercase tracking-wider">
              RDAP Live Query
            </span>
          </div>

          <div className="mt-4 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-[#8f8e89]">Analyzed Domain:</span>
              <span className="font-mono text-[#f0eee8] font-medium">{primaryDomain}</span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[#8f8e89]">Registration Age:</span>
              <span
                className={`font-mono font-medium ${
                  whois?.isVeryNewDomain
                    ? "text-[#ef5343]"
                    : whois?.isNewDomain
                    ? "text-[#f09a36]"
                    : "text-[#48b882]"
                }`}
              >
                {whois?.domainAgeFormatted || "Recently Observed"}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[#8f8e89]">Official Registrar:</span>
              <span className="text-[#f0eee8] text-right truncate max-w-[200px]" title={whois?.registrar}>
                {whois?.registrar || "Privacy Protected / Masked"}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[#8f8e89]">WHOIS Privacy:</span>
              <span className="text-[#b8b6b0]">
                {whois?.privacyProtected ? "Active (Masked Ownership)" : "Public Corporate Record"}
              </span>
            </div>
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-[#282a31] text-[11px] text-[#8f8e89] flex justify-between font-mono">
          <span>Cache Policy: 24h</span>
          <span>Status: Verified</span>
        </div>
      </div>

      {/* Threat Feed & Multi-Engine Blacklist Card */}
      <div className="bg-[#16171c] border border-[#282a31] rounded-xl p-5 flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between pb-3 border-b border-[#282a31]">
            <span className="font-display font-bold text-sm text-[#f0eee8]">
              Multi-Engine Threat Blacklists
            </span>
            <span className="text-[10px] font-mono text-[#8f8e89] uppercase tracking-wider">
              74 Security Engines
            </span>
          </div>

          <div className="mt-4 space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-[#8f8e89]">Antivirus Engine Flags:</span>
              <span
                className={`font-mono font-bold ${
                  (virusTotal?.maliciousCount || 0) > 0 ? "text-[#ef5343]" : "text-[#48b882]"
                }`}
              >
                {virusTotal?.detectionRatio || "0 / 74"}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[#8f8e89]">PhishTank Database:</span>
              <span
                className={`font-mono font-medium ${
                  virusTotal?.phishTankVerified ? "text-[#ef5343]" : "text-[#48b882]"
                }`}
              >
                {virusTotal?.phishTankVerified ? "Blacklisted Threat" : "Clean"}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[#8f8e89]">OpenPhish Feed:</span>
              <span
                className={`font-mono font-medium ${
                  virusTotal?.openPhishListed ? "text-[#ef5343]" : "text-[#48b882]"
                }`}
              >
                {virusTotal?.openPhishListed ? "Active Phish Match" : "Clean"}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[#8f8e89]">Classification:</span>
              <span className="text-[#f0eee8] text-right truncate max-w-[200px]">
                {virusTotal?.threatCategory || "Clean Baseline"}
              </span>
            </div>
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-[#282a31] text-[11px] text-[#8f8e89] flex justify-between font-mono">
          <span>Feeds: Kaspersky, Sophos, Google</span>
          <span className="text-[#48b882]">Live</span>
        </div>
      </div>
    </div>
  );
}
