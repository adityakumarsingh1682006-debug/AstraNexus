---
name: ui-ux-pro-max
description: >-
  Advanced UI/UX engineering, design systems, cybersecurity aesthetic specialization,
  accessibility (WCAG AAA), and mobile-first responsive architecture.
---

# UI/UX Pro Max: Engineering & Design System Standard

## 1. Core Design Philosophy: Astra Cybernetic Identity
AstraNexus is a defense-grade security platform. Its aesthetic must communicate precision, authority, speed, and trust.

### Guiding Tenets:
1. **Never Generic**: Reject generic SaaS dashboard templates (e.g. pastel purple cards, decorative meaningless charts, fake metric counters).
2. **Technical Authenticity**: Design like an advanced SOC console (Palantir Gotham, CrowdStrike Falcon, Cloudflare Radar, Bloomberg Terminal).
3. **Information Hierarchy**:
   - Tier 1: Actionable Threat Verdict & Instant Action (Kill switch / Quarantine / Scan).
   - Tier 2: Forensic Evidence Telemetry (DNS, SSL, Typosquatting, URLhaus).
   - Tier 3: Explanatory Context (Gemini plain-language breakdown & recommendations).
   - Tier 4: Cryptographic Seals (EVM testnet hashes, canonical digests).
4. **Purposeful Feedback**: Every user interaction must produce immediate visual feedback (loading spinners, scan steppers, status badges, toast feedback). No inert buttons.

---

## 2. Color Palette & Semantic Design Tokens

### Surface & Background Tokens
- `bg-astra-void` (`#04070D`): Deep space black void. Eliminates screen glare, maximizes battery efficiency on OLED displays.
- `bg-astra-deep` (`#060A12`): Ambient backdrop.
- `bg-astra-card` (`#0C121E`): Base panel surface with 1px border `rgba(0, 240, 255, 0.12)`.
- `bg-astra-elevated` (`#121A2B`): Elevated interactive card surface.
- `border-astra-border` (`#1E293B`): Neutral structural boundary.

### Telemetry & Severity Accents
- **Primary Telemetry**: Astra Cyan (`#00F0FF`, Glow: `rgba(0, 240, 255, 0.35)`). Active scanning, target selection, primary CTAs.
- **AI & Correlation**: Plasma Violet (`#8B5CF6`, Glow: `rgba(139, 92, 246, 0.35)`). Cognitive reasoning, topological graph edges.
- **Critical Malicious**: Threat Crimson (`#EF4444`, Glow: `rgba(239, 68, 68, 0.35)`). Score 70-100, credential harvester, malware.
- **High Suspicious**: Warning Amber (`#F59E0B`, Glow: `rgba(245, 158, 11, 0.30)`). Score 35-69, typosquats, self-signed certs.
- **Verified Clean**: Safe Emerald (`#10B981`, Glow: `rgba(16, 185, 129, 0.30)`). Score 0-34, verified legitimate domains.

---

## 3. Typography Architecture

- **UI Headings & Interface Copy**: High-legibility modern sans (`Geist Sans`, `Inter`, `system-ui`).
- **Telemetry, Hashes & Cryptographic Tokens**: Technical Monospace (`Geist Mono`, `JetBrains Mono`, `ui-monospace`).
  - All URLs, IP addresses, ASNs, hashes, DNS records, and CVEs MUST use monospace formatting.
- **Contrast Ratios**:
  - Primary text on dark backgrounds: `#F8FAFC` (Contrast ratio > 15:1, exceeds WCAG AAA).
  - Secondary labels: `#94A3B8` (Contrast ratio > 7:1, exceeds WCAG AA).
  - Muted technical descriptors: `#64748B` (Contrast ratio > 4.5:1).

---

## 4. Accessibility (a11y) & Usability

- **Keyboard Navigation**: All interactive elements (buttons, inputs, accordions, tabs) must provide visible focus rings:
  `focus-visible:ring-2 focus-visible:ring-astra-cyan focus-visible:outline-none`.
- **Screen Reader Support**:
  - Live scanning progress uses `role="status"` and `aria-live="polite"`.
  - Icon-only buttons must have descriptive `aria-label`.
- **Motion Reduction**:
  - Wrap continuous animations (e.g. radar sweep, pulsating badges) with `@media (prefers-reduced-motion: reduce)`.

---

## 5. Mobile-First & Responsive Ergonomics

- Minimum touch target: 44x44px (`min-h-[44px]`).
- Clean mobile drawer navigation with high-contrast active states.
- Tables must feature horizontal scroll wrappers with sticky indicators or transform into mobile card feeds.
- Prevent layout shifts (CLS = 0) with explicit aspect ratios on radar and visualizers.
