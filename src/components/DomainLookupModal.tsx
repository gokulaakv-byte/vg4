"use client";

import React, { useState } from "react";
import { Search, X } from "lucide-react";
import { WhoisResult, VirusTotalResult } from "@/lib/threat-intel";

interface DomainLookupModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function DomainLookupModal({ isOpen, onClose }: DomainLookupModalProps) {
  const [queryDomain, setQueryDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [lookupResult, setLookupResult] = useState<{
    domain: string;
    whois: WhoisResult;
    virusTotal: VirusTotalResult;
  } | null>(null);

  if (!isOpen) return null;

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!queryDomain.trim()) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/lookup-domain?domain=${encodeURIComponent(queryDomain.trim())}`);
      if (res.ok) {
        const data = await res.json();
        setLookupResult(data);
      }
    } catch (err) {
      console.error("Lookup error:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#1b1d22] border border-[#282a31] rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl">
        <div className="p-5 border-b border-[#282a31] flex items-center justify-between bg-[#16171c]">
          <h3 className="font-display font-bold text-base text-[#f0eee8]">
            WHOIS & Threat Intelligence Lookup
          </h3>
          <button onClick={onClose} className="text-[#8f8e89] hover:text-[#f0eee8] p-1">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          <form onSubmit={handleSearch} className="flex gap-2">
            <input
              type="text"
              value={queryDomain}
              onChange={(e) => setQueryDomain(e.target.value)}
              placeholder="Enter domain (e.g. chase-fraud-verify9.xyz or github.com)"
              className="w-full bg-[#111215] border border-[#282a31] rounded-lg px-3 py-2.5 text-xs font-mono text-[#f0eee8] placeholder:text-[#6d6c67] focus:outline-none focus:border-[#8f8e89]"
            />
            <button
              type="submit"
              disabled={loading}
              className="bg-[#282a31] hover:bg-[#343740] text-[#f0eee8] font-medium px-4 py-2 rounded-lg text-xs shrink-0 flex items-center gap-1.5 transition-colors"
            >
              <Search className="w-3.5 h-3.5" />
              {loading ? "Querying..." : "Query"}
            </button>
          </form>

          {lookupResult && (
            <div className="border border-[#282a31] rounded-xl p-4 bg-[#141519] space-y-3 text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-[#282a31]">
                <span className="font-mono text-sm text-[#f0eee8]">
                  {lookupResult.domain}
                </span>
                <span
                  className={`text-[10px] font-mono uppercase px-2 py-0.5 border rounded ${
                    lookupResult.whois.isVeryNewDomain
                      ? "text-[#ef5343] border-[#d9483b]/40 bg-[#d9483b]/10"
                      : "text-[#48b882] border-[#389e6e]/40 bg-[#389e6e]/10"
                  }`}
                >
                  {lookupResult.whois.isVeryNewDomain ? "High-Risk Domain" : "Established"}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3 text-[#b8b6b0]">
                <div>
                  <span className="text-[#8f8e89] block text-[11px]">Registration Age:</span>
                  <span className="font-mono text-[#f0eee8]">
                    {lookupResult.whois.domainAgeFormatted}
                  </span>
                </div>
                <div>
                  <span className="text-[#8f8e89] block text-[11px]">Registrar:</span>
                  <span className="text-[#f0eee8] truncate block">
                    {lookupResult.whois.registrar}
                  </span>
                </div>
                <div>
                  <span className="text-[#8f8e89] block text-[11px]">Antivirus Flags:</span>
                  <span
                    className={`font-mono ${
                      lookupResult.virusTotal.maliciousCount > 0 ? "text-[#ef5343]" : "text-[#48b882]"
                    }`}
                  >
                    {lookupResult.virusTotal.detectionRatio}
                  </span>
                </div>
                <div>
                  <span className="text-[#8f8e89] block text-[11px]">PhishTank Status:</span>
                  <span className="font-mono text-[#f0eee8]">
                    {lookupResult.virusTotal.phishTankVerified ? "Blacklisted Threat" : "Clean Baseline"}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
