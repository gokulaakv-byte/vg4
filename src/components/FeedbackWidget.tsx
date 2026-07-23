"use client";

import React, { useState } from "react";
import { ThumbsUp, ThumbsDown, Check } from "lucide-react";

interface FeedbackWidgetProps {
  reportId: string;
}

export function FeedbackWidget({ reportId }: FeedbackWidgetProps) {
  const [submitted, setSubmitted] = useState<"up" | "down" | null>(null);
  const [loading, setLoading] = useState(false);
  const [showReasonBox, setShowReasonBox] = useState(false);
  const [reason, setReason] = useState("");

  const handleVote = async (type: "up" | "down") => {
    setLoading(true);
    try {
      await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          reportId,
          feedbackType: type,
          feedbackReason: reason || undefined,
        }),
      });
      setSubmitted(type);
      setShowReasonBox(false);
    } catch (err) {
      console.error("Feedback vote error:", err);
      setSubmitted(type);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-[#16171c] border border-[#282a31] rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3">
      <div>
        <h4 className="text-xs sm:text-sm font-display font-bold text-[#f0eee8]">
          Was this threat assessment accurate?
        </h4>
        <p className="text-[11px] text-[#8f8e89]">
          Your feedback calibrates scoring algorithms and prevents false positive alerts.
        </p>
      </div>

      {submitted ? (
        <div className="flex items-center gap-2 text-xs font-mono text-[#48b882] bg-[#389e6e]/10 px-3 py-1.5 rounded border border-[#389e6e]/30">
          <Check className="w-3.5 h-3.5" /> Assessment rating recorded
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleVote("up")}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#1f2127] hover:bg-[#282a31] text-[#f0eee8] text-xs font-medium border border-[#282a31] transition-colors"
          >
            <ThumbsUp className="w-3.5 h-3.5" /> Accurate
          </button>
          <button
            onClick={() => setShowReasonBox(true)}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#1f2127] hover:bg-[#282a31] text-[#f0eee8] text-xs font-medium border border-[#282a31] transition-colors"
          >
            <ThumbsDown className="w-3.5 h-3.5" /> Inaccurate
          </button>
        </div>
      )}

      {showReasonBox && !submitted && (
        <div className="w-full mt-3 pt-3 border-t border-[#282a31] flex flex-col gap-2">
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Optional context: e.g., Legitimate internal company notice"
            className="w-full bg-[#111215] border border-[#282a31] rounded px-3 py-1.5 text-xs text-[#f0eee8] focus:outline-none focus:border-[#8f8e89]"
          />
          <div className="flex justify-end gap-2">
            <button
              onClick={() => setShowReasonBox(false)}
              className="text-xs text-[#8f8e89] hover:text-[#f0eee8] px-2 py-1"
            >
              Cancel
            </button>
            <button
              onClick={() => handleVote("down")}
              className="text-xs bg-[#d9483b] hover:bg-[#ef5343] text-white font-medium px-3 py-1 rounded transition-colors"
            >
              Submit Note
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
