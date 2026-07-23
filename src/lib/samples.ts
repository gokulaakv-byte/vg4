export interface PhishSample {
  id: string;
  name: string;
  category: "SMS" | "Email" | "Invoice Scam" | "BEC" | "Safe / Legitimate";
  sender: string;
  subject?: string;
  text: string;
  expectedRisk: "High Risk (90+)" | "High Risk (85+)" | "Caution (45+)" | "Safe (0-15)";
  badgeColor: string;
  description: string;
}

export const PHISH_SAMPLES: PhishSample[] = [
  {
    id: "chase_sms_phish",
    name: "Urgent Chase Bank Alert (SMS)",
    category: "SMS",
    sender: "+1 (833) 948-2811",
    text: `CHASE BANK ALERT: Unauthorized debit attempt of $1,489.99 detected on your card. If this wasn't you, IMMEDIATELY verify your account at https://chase-fraud-verify9.xyz/auth or your account will be permanently frozen within 2 hours.`,
    expectedRisk: "High Risk (90+)",
    badgeColor: "bg-red-500/15 text-red-400 border-red-500/30",
    description: "Typosquatted domain (.xyz TLD), intense psychological urgency, credential harvesting link.",
  },
  {
    id: "geeksquad_invoice",
    name: "Geek Squad Fake Auto-Renewal ($499)",
    category: "Invoice Scam",
    sender: "Geek Squad Support <billing-department@geeksquad-renew-secure.top>",
    subject: "INVOICE #GS-99482: Auto-renewal completed successfully ($499.00 USD)",
    text: `Dear Customer,

Thank you for your business! Your annual Geek Squad Total Tech Care subscription has been automatically renewed for $499.00 USD and charged to your checking account.

If you did not authorize this renewal or wish to claim a FULL REFUND immediately, please click here: https://geeksquad-renew-secure.top/refund-portal or call our dispute desk at 1-800-555-0199 within 24 hours.

Transaction ID: #GS-99482
Amount: $499.00 USD
Status: Paid / Settled`,
    expectedRisk: "High Risk (90+)",
    badgeColor: "bg-red-500/15 text-red-400 border-red-500/30",
    description: "Classic fake invoice refund lure, impersonating GeekSquad with fake .top domain.",
  },
  {
    id: "m365_password_phish",
    name: "Microsoft 365 Password Expiration",
    category: "Email",
    sender: "IT Helpdesk Security <no-reply@microsoft-security-portal-verify.com>",
    subject: "URGENT: Your Microsoft 365 Password Expires in 2 Hours",
    text: `Attention Employee,

Your Microsoft 365 organizational password is scheduled to expire today. All active access tokens and Outlook email sync will be disabled unless you retain your existing credentials.

Keep current password here:
https://microsoft-security-portal-verify.com/login?session=active

IT Security Administration
Office 365 Global Operations`,
    expectedRisk: "High Risk (85+)",
    badgeColor: "bg-red-500/15 text-red-400 border-red-500/30",
    description: "Workplace credential harvesting using brand spoofing and artificial urgency.",
  },
  {
    id: "docusign_spoof",
    name: "DocuSign Urgent Signature Request",
    category: "Email",
    sender: "DocuSign System <docusign-notification@secure-docs-review.click>",
    subject: "Please DocuSign: Confidential Settlement & Severance Agreement.pdf",
    text: `DocuSign Electronic Signature Service

You have received a confidential document requiring immediate signature: "Executive_Severance_Package_2026.pdf".

View Document & Complete Signature:
https://secure-docs-review.click/docusign/sign-now?env=prod

Please complete this within 4 hours.
DocuSign, Inc.`,
    expectedRisk: "High Risk (90+)",
    badgeColor: "bg-red-500/15 text-red-400 border-red-500/30",
    description: "Curiosity & fear lure impersonating DocuSign with a .click high-risk TLD.",
  },
  {
    id: "ceo_wire_bec",
    name: "CEO Urgent Wire Transfer (BEC)",
    category: "BEC",
    sender: "David Marcus <ceo-confidential-desk@gmail.com>",
    subject: "Quick favor - urgent acquisition wire",
    text: `Are you at your desk right now?

I am stuck in a confidential board meeting for an acquisition and need you to process an urgent wire transfer of $42,500 to our external escrow vendor before 4 PM today.

Send me your direct mobile or reply immediately so I can send the banking routing instructions. Keep this confidential.

David Marcus, Chief Executive Officer`,
    expectedRisk: "Caution (45+)",
    badgeColor: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    description: "Business Email Compromise (BEC) with display-name spoofing from a free @gmail.com account.",
  },
  {
    id: "github_safe_2fa",
    name: "Legitimate GitHub 2FA Code (Safe)",
    category: "Safe / Legitimate",
    sender: "GitHub <noreply@github.com>",
    subject: "[GitHub] Please verify your device",
    text: `Hey security-learner,

A sign-in attempt was made to your GitHub account from Chrome on macOS (IP: 198.51.100.42 - Seattle, WA).

Your verification code is: 839201

This code will expire in 10 minutes. If this was not you, you can check your account security settings at https://github.com/settings/security.

GitHub, Inc. 88 Colin P Kelly Jr St, San Francisco, CA 94107`,
    expectedRisk: "Safe (0-15)",
    badgeColor: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    description: "Legitimate notification from verified github.com domain with zero coercive phishing indicators.",
  },
];
