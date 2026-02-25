# TrustProbe AI — Technical Documentation

> Comprehensive technical reference for the TrustProbe AI multi-modal phishing detection platform. For a quick overview, see [README.md](README.md).

---

## Table of Contents

- [1. System Overview](#1-system-overview)
- [2. Architecture Deep Dive](#2-architecture-deep-dive)
- [3. URL Detection Engine](#3-url-detection-engine)
- [4. Email Detection Engine](#4-email-detection-engine)
- [5. AI Integration (Llama 3.3 70B)](#5-ai-integration-llama-33-70b)
- [6. Benchmark & Evaluation](#6-benchmark--evaluation)
- [7. Data Models](#7-data-models)
- [8. UI Components](#8-ui-components)
- [9. Device Identity & Data Ownership](#9-device-identity--data-ownership)
- [10. Firebase Firestore Schema](#10-firebase-firestore-schema)
- [11. Dependency Injection](#11-dependency-injection)
- [12. Configuration Reference](#12-configuration-reference)
- [13. Error Handling & Graceful Degradation](#13-error-handling--graceful-degradation)
- [14. Security Considerations](#14-security-considerations)
- [15. Future Roadmap](#15-future-roadmap)
- [16. Troubleshooting](#16-troubleshooting)

---

## 1. System Overview

TrustProbe AI is a Flutter Web application that detects phishing in **URLs and emails** using a **multi-modal detection engine** inspired by deep learning architectures:

### URL Analysis Pipeline

```
User enters URL
       │
       v
PhishingService.analyzeUrl()
       │
       v
┌──────────────────────────────────────────┐
│          MultiModalEngine.analyze()       │
│                                           │
│  ┌─────────────┐  ┌──────────────────┐   │
│  │ URL Features │  │ Sequential       │   │
│  │ (CNN-equiv)  │  │ Patterns (LSTM)  │   │
│  │ 25+ features │  │ 8 features       │   │
│  └──────┬───────┘  └───────┬──────────┘   │
│         │                  │              │
│  ┌──────┴──────┐  ┌───────┴──────────┐   │
│  │ Host/Domain │  │ SSL/Security     │   │
│  │ 10 features │  │ 5 features       │   │
│  └──────┬──────┘  └───────┬──────────┘   │
│         │                  │              │
│  ┌──────┴──────────────────┴──────────┐   │
│  │    Content Analysis (7 features)   │   │
│  └────────────────┬───────────────────┘   │
│                   │                       │
│         Weighted combination → Score       │
└──────────────────┬────────────────────────┘
                   │
                   v
            AiService (optional)
           Llama 3.3 70B via Groq
                   │
                   v
         ScanResult (final output)
```

### Email Analysis Pipeline

```
User pastes email text
       │
       v
EmailPhishingService.analyzeEmail()
       │
       ├──> EmailParser.parse()  →  ParsedEmail
       │
       v
EmailMultiModalEngine.analyze()
       │
       ├──> EmailHeaderAnalyzer  (sender reputation, spoofing)
       ├──> EmailContentAnalyzer (urgency, credential requests)
       ├──> MultiModalEngine     (each embedded URL)
       └──> Metadata analysis    (HTML ratio, link density)
       │
       v
AiService → EmailScanResult
```

### Design Principles

1. **Multi-modal fusion** — No single check determines the classification; all modalities contribute weighted scores.
2. **Graceful degradation** — AI, Firebase, and individual modalities can fail without crashing.
3. **Offline-capable** — Heuristic analysis works fully offline; only AI and Firestore require network.
4. **Research-grade accuracy** — Calibrated against PhishTank, OpenPhish, and Alexa Top Sites datasets.

---

## 2. Architecture Deep Dive

### Pattern: Stacked MVVM

The [Stacked](https://pub.dev/packages/stacked) framework provides:

- **Reactive ViewModels** — Extend `BaseViewModel`, call `notifyListeners()` for UI updates.
- **Service Locator** — `get_it` for DI. All 16 services registered as lazy singletons.
- **Code Generation** — Routes and locator from `app.dart` annotations.

### Service Dependency Graph

```
PhishingService
  └─ MultiModalEngine
       ├─ UrlFeatureExtractor
       ├─ SequentialAnalyzer
       ├─ HostAnalysisService
       ├─ SslAnalysisService
       └─ ContentAnalysisService
  └─ AiService

EmailPhishingService
  ├─ EmailParser
  └─ EmailMultiModalEngine
       ├─ EmailHeaderAnalyzer
       ├─ EmailContentAnalyzer
       ├─ MultiModalEngine (reused for embedded URLs)
       └─ (metadata analysis — inline)
  └─ AiService

BenchmarkService
  └─ MultiModalEngine
  └─ PhishingDataset

HomeViewModel
  ├─ PhishingService
  ├─ EmailPhishingService
  ├─ FirestoreService
  └─ DeviceIdService
```

---

## 3. URL Detection Engine

### 3.1 UrlFeatureExtractor (CNN-equivalent)

**File:** `lib/services/url_feature_extractor.dart` (172 lines)

Extracts 25+ numeric features from URL strings, mirroring character-level patterns a CNN would learn:

| Feature | Type | Description |
|---------|------|-------------|
| `entropy` | `double` | Shannon entropy — high entropy = randomness |
| `urlLength` | `int` | Total URL length |
| `domainLength` | `int` | Domain portion length |
| `pathLength` | `int` | Path portion length |
| `dotCount` | `int` | Number of dots |
| `dashCount` | `int` | Number of dashes |
| `underscoreCount` | `int` | Number of underscores |
| `digitCount` / `digitRatio` | `int` / `double` | Digit frequency |
| `specialCharCount` / `specialCharRatio` | `int` / `double` | Special character frequency |
| `uppercaseCount` / `uppercaseRatio` | `int` / `double` | Case anomalies |
| `pathDepth` | `int` | Directory nesting level |
| `queryParamCount` | `int` | Number of query parameters |
| `hasFragment` / `hasPort` / `hasNonStandardPort` | `bool` | Structural flags |
| `longestConsonantRun` | `int` | Max consecutive consonants (randomness indicator) |
| `repeatedCharSequences` | `int` | Triple-character repetitions |
| `vowelConsonantRatio` | `double` | Consonant-heavy = suspicious |
| `charVariety` | `double` | Unique chars / total length |
| `avgWordLengthInDomain` | `double` | Domain "word" lengths |
| `subdomainCount` | `int` | Number of subdomain levels |
| `domainIsHexLike` | `bool` | >80% hex chars in domain |
| `atSymbolCount` | `int` | URL obfuscation indicator |

---

### 3.2 SequentialAnalyzer (LSTM-equivalent)

**File:** `lib/services/sequential_analyzer.dart` (262 lines)

Analyzes character sequences and transitions:

| Feature | Description |
|---------|-------------|
| `charTransitionScore` | Character type transition anomalies (L→D, D→S, etc.) |
| `tokenAnomalyScore` | Anomalous URL token patterns |
| `positionalDistribution` | Character type distribution across URL positions |
| `bigramAnomaly` | Domain bigram frequency vs. English norms |
| `typeDirectionChanges` | Count of character type direction changes |
| `maxTokenLengthRatio` | Ratio of longest to average token |
| `anomalousSubsequences` | Count of random-looking substrings |
| `randomSegmentRatio` | Proportion of random-looking URL segments |

---

### 3.3 HostAnalysisService

**File:** `lib/services/host_analysis_service.dart` (277 lines)

| Feature | Description |
|---------|-------------|
| `tldRiskScore` | 0–1 score from a database of 60+ TLDs with risk weights |
| `domainStructureRisk` | Length, dashes, dots, digits in domain |
| `brandImpersonationScore` | Confidence of brand mimicry (29 brands tracked) |
| `isIpAddress` | Raw IPv4 used as domain |
| `isUrlShortener` | 14 known shortener services |
| `subdomainDepth` | Number of subdomain levels |
| `domainRandomnessScore` | Vowel ratio + entropy heuristic |
| `impersonatedBrand` | Name of impersonated brand (if detected) |
| `isTrustedDomain` | Matches 35+ whitelisted domains |
| `domainAgeRisk` | Heuristic age estimation (TLD + structure) |

**Trusted domains list:** 35+ entries including Google, Facebook, Microsoft, Amazon, Apple, Twitter, LinkedIn, GitHub, PayPal, Netflix, Spotify, banking institutions (Chase, Wells Fargo, Citi, HSBC, Barclays), and cloud providers (AWS, Azure).

**Brand impersonation:** 29 brands tracked. Detects when a domain *contains* a brand name but *isn't* the official domain. Higher confidence when combined with suspicious TLDs.

---

### 3.4 SslAnalysisService

**File:** `lib/services/ssl_analysis_service.dart` (109 lines)

| Feature | Description |
|---------|-------------|
| `isHttps` | Whether URL uses HTTPS |
| `hasFreeSSLIndicators` | Domain on known free hosting (14 patterns) |
| `securityScore` | Composite: HTTPS + standard port + URL cleanliness |
| `hasMixedContentIndicators` | HTTP references within HTTPS URLs |
| `hasRedirectPatterns` | 16 redirect parameter patterns (e.g., `redirect=`, `goto=`, `next=`) |

---

### 3.5 ContentAnalysisService

**File:** `lib/services/content_analysis_service.dart` (199 lines)

| Feature | Description |
|---------|-------------|
| `suggestsLoginPage` | 15 login keywords in URL path/query |
| `hasFormIndicators` | 14 form/registration keywords |
| `suggestsDownload` | 22 download/malware file patterns |
| `hasDataExfiltrationPatterns` | 19 data theft keywords (SSN, credit card, crypto) |
| `mimicsLegitimateService` | 24 service impersonation keywords |
| `urlPathContentRisk` | Composite path risk score |
| `credentialKeywords` | List of detected credential-related keywords |

---

### 3.6 MultiModalEngine (Fusion)

**File:** `lib/services/multi_modal_engine.dart` (341 lines)

Combines all 5 modalities using weighted scoring:

| Modality | Base Weight |
|----------|-------------|
| URL Features (CNN) | 25% |
| Sequential (LSTM) | 20% |
| Host/Domain | 25% |
| SSL/Security | 15% |
| Content | 15% |

**Score boosters:**
- Trusted domain detected → −40 points
- Brand impersonation + high-risk host → up to +30 points
- Non-HTTPS → +15 points
- IP address usage → +20 points

**Classification thresholds:** ≤40 = Safe, ≤70 = Suspicious, 71+ = Malicious.

---

## 4. Email Detection Engine

### 4.1 EmailParser

**File:** `lib/services/email_parser.dart` (263 lines)

Handles both full email (with headers) and body-only input:

- **Header parsing:** Extracts `From`, `To`, `Subject`, `Reply-To`, `Return-Path`, `Received`, `Message-ID`.
- **URL extraction:** Plain text URLs, HTML `href` attributes, MIME-encoded `=3D"..."` links.
- **Output:** `ParsedEmail` with `senderEmail`, `senderDomain`, `senderDisplayName`, `replyToEmail`, `subject`, `body`, `embeddedUrls`, `rawHeaders`.

---

### 4.2 EmailHeaderAnalyzer

**File:** `lib/services/email_header_analyzer.dart` (251 lines)

| Feature | Description |
|---------|-------------|
| `senderDomainRisk` | 0–1 score based on TLD and known brand domains |
| `isFreeEmailProvider` | 15 free providers (Gmail, Yahoo, etc.) |
| `hasReplyToMismatch` | Reply-To differs from sender |
| `displayNameImpersonation` | Display name contains brand but domain doesn't match |
| `hasSpoofingIndicators` | Domain contains brand name but isn't official |
| `brandSpoofScore` | Confidence of brand spoofing |
| `impersonatedBrand` | Name of detected brand (14 brands with domain lists) |
| `headerAnomalyCount` | Count of structural anomalies |

---

### 4.3 EmailContentAnalyzer

**File:** `lib/services/email_content_analyzer.dart` (309 lines)

Pattern detection with scored results:

| Analysis | Patterns Tracked | Score Logic |
|----------|-----------------|-------------|
| **Urgency** | 28 patterns (`urgent`, `act now`, `expires today`, etc.) | 3+ matches = max score |
| **Credential Requests** | 29 patterns (`verify your account`, `reset password`, etc.) | 2+ matches = max score |
| **Social Engineering** | 26 patterns (`dear customer`, `we have detected`, etc.) | 3+ matches = max score |
| **Financial Lures** | 28 patterns (`you have won`, `gift card`, `cryptocurrency`, etc.) | 2+ matches = max score |
| **Threat Language** | 23 patterns (`legal action`, `suspended`, `blocked`, etc.) | 2+ matches = max score |
| **Grammar Anomalies** | Exclamation marks, capitalization ratio, short body with link, repeated punctuation | Composite score |
| **Authority Impersonation** | 19 patterns (`CEO`, `IT Department`, `IRS`, etc.) | Boolean |

---

### 4.4 EmailMultiModalEngine

**File:** `lib/services/email_multi_modal_engine.dart` (354 lines)

Combines 4 email modalities:

| Modality | Weight | Source |
|----------|--------|--------|
| Header Analysis | 30% | `EmailHeaderAnalyzer` |
| Content Analysis | 30% | `EmailContentAnalyzer` |
| Embedded URL Analysis | 25% | `MultiModalEngine` (reused) |
| Metadata Analysis | 15% | Inline (HTML ratio, link density, etc.) |

**Embedded URL analysis:** Each URL found in the email is run through the full 5-modality URL engine. The email receives the highest risk URL's score.

---

## 5. AI Integration (Llama 3.3 70B)

**File:** `lib/services/ai_service.dart` (236 lines)

### Provider: Groq API

| Setting | Value |
|---------|-------|
| **Endpoint** | `https://api.groq.com/openai/v1/chat/completions` |
| **Model** | `llama-3.3-70b-versatile` |
| **Temperature** | `0.3` |
| **Max tokens** | `1024` |
| **Response format** | JSON object (enforced) |
| **Timeout** | 15 seconds |

### Enhanced Prompt

The system prompt now references all 5 modalities by name (CNN, LSTM, Host, SSL, Content) and instructs the LLM to:
1. Reference multi-modal analysis components in its assessment.
2. Receive per-modality scores as context.
3. Consider domain age implications and URL obfuscation techniques.
4. Identify specific phishing techniques (typosquatting, homograph attacks, brand impersonation).

### Response Format

```json
{
  "threatSummary": "Concise 1-2 sentence summary",
  "riskFactors": ["factor1", "factor2", "factor3"],
  "recommendation": "Actionable user guidance",
  "confidenceLevel": "high|medium|low"
}
```

---

## 6. Benchmark & Evaluation

**Files:** `lib/services/benchmark_service.dart` (182 lines), `lib/data/phishing_dataset.dart` (464 lines)

### Dataset Composition

| Category | Source | Count | Examples |
|----------|--------|-------|---------|
| Brand impersonation (PayPal, Apple, Microsoft, Google, Amazon, Facebook, Banking, Netflix) | PhishTank / OpenPhish | ~45 | `paypal-login-verification.tk` |
| IP-based phishing | PhishTank / OpenPhish | 5 | `192.168.1.1/admin/login` |
| URL shortener abuse | OpenPhish / PhishTank | 4 | `bit.ly/3xF2q` |
| Obfuscation techniques | PhishTank / OpenPhish | 3 | `google.com@evil.tk/login` |
| Random domains | OpenPhish / PhishTank | 4 | `xkjf7823ksd.tk/signin` |
| Long/complex URLs | PhishTank / OpenPhish | 3 | 50+ char phishing URLs |
| Suspicious TLDs | OpenPhish / PhishTank | 5 | `.buzz`, `.icu`, `.click`, etc. |
| Crypto/wallet | PhishTank / OpenPhish | 4 | `metamask-wallet-sync.tk` |
| Data exfiltration | PhishTank / OpenPhish | 3 | `verify-ssn-tax-refund.tk` |
| Homograph/typosquatting | PhishTank / OpenPhish | 5 | `g00gle.com`, `arnazon.com` |
| Subdomain abuse | PhishTank / OpenPhish | 4 | `login.paypal.com.evil.tk` |
| Redirect abuse | PhishTank / OpenPhish | 2 | `redirect=http://evil.com` |
| **Safe URLs** | Alexa Top Sites | ~80 | `google.com`, `github.com`, `mit.edu` |

### Metrics

```dart
accuracy = (truePositives + trueNegatives) / totalSamples
precision = truePositives / (truePositives + falsePositives)
recall = truePositives / (truePositives + falseNegatives)
f1Score = 2 * (precision * recall) / (precision + recall)
```

Per-source accuracy breakdown is also computed (PhishTank vs. OpenPhish vs. Alexa).

---

## 7. Data Models

### ScanResult (URL)

**File:** `lib/models/scan_result.dart` (125 lines)

| Field | Type | Description |
|-------|------|-------------|
| `url` | `String` | The analyzed URL |
| `riskScore` | `int` | 0–100 risk percentage |
| `classification` | `String` | Safe / Suspicious / Malicious |
| `reason` | `String` | Human-readable explanation |
| `timestamp` | `DateTime` | Scan time |
| `aiAnalysis` | `String?` | AI analysis text |
| `deviceId` | `String?` | Device UUID |
| `scoreBreakdown` | `Map<String, int>` | Per-check scores |
| `modalityScores` | `Map<String, double>` | Per-modality scores (0–100) |
| `modalityExplanations` | `Map<String, String>` | Per-modality explanations |
| `featureCount` | `int` | Total features extracted |

### EmailScanResult

**File:** `lib/models/email_scan_result.dart` (172 lines)

All `ScanResult` fields plus:

| Field | Type | Description |
|-------|------|-------------|
| `senderEmail` | `String?` | Extracted sender |
| `subject` | `String?` | Email subject |
| `bodyPreview` | `String` | First 200 chars of body |
| `embeddedUrlCount` | `int` | URLs found in email |
| `highestRiskUrl` | `String?` | Most dangerous embedded URL |
| `highestRiskUrlScore` | `int?` | Risk score of that URL |
| `scanType` | `String` | Always `"email"` |

### Feature Models

| File | Lines | Classes |
|------|-------|---------|
| `feature_set.dart` | 745 | `UrlFeatures`, `SequentialFeatures`, `HostFeatures`, `SslFeatures`, `ContentFeatures`, `MultiModalFeatureSet` |
| `email_feature_set.dart` | 376 | `EmailHeaderFeatures`, `EmailContentFeatures`, `EmailUrlFeatures`, `EmailMetadataFeatures`, `EmailMultiModalFeatureSet` |

---

## 8. UI Components

### HomeView (`home_view.dart`)

Main screen with URL input, email input (tab-based), result display, and scan history.

### ResultCard (`result_card.dart`, 37K)

URL analysis result with:
- Animated risk score gauge
- Classification badge
- Per-modality score bars
- AI insights section (expandable)
- Score breakdown dropdown

### EmailResultCard (`email_result_card.dart`, 36K)

Email analysis result with:
- Sender info and subject display
- Per-modality scores (Header, Content, URL, Metadata)
- Highest-risk embedded URL highlight
- AI insights and recommendations

### SearchHistoryTable (`search_history_table.dart`, 11K)

Real-time history from Firestore via `StreamBuilder`. Responsive: table on desktop, cards on mobile.

---

## 9. Device Identity & Data Ownership

**File:** `lib/services/device_id_service.dart`

- Generates UUID v4 per device, persisted via `SharedPreferences`.
- Storage key: `trustprobe_device_id`.
- All Firestore queries filtered by `deviceId`.
- Fallback: in-memory UUID if storage fails.

**Migration path:** When auth is added, query by `deviceId` → update to `userId` → switch queries.

---

## 10. Firebase Firestore Schema

### Collection: `url_scans`

| Field | Type | Example |
|-------|------|---------|
| `url` | `string` | `"https://google.com"` |
| `riskScore` | `number` | `15` |
| `classification` | `string` | `"Safe"` |
| `reason` | `string` | `"Trusted domain..."` |
| `timestamp` | `string` | `"2026-02-25T..."` |
| `deviceId` | `string` | `"550e8400-..."` |
| `modalityScores` | `map` | `{"URL Features": 12.5, ...}` |
| `modalityExplanations` | `map` | `{"URL Features": "Low entropy..."}` |
| `featureCount` | `number` | `55` |
| `aiAnalysis` | `string` (opt) | `"AI Threat Summary: ..."` |
| `scoreBreakdown` | `map` (opt) | `{"Trusted Domain": -40}` |

### Required Composite Index

```
Collection: url_scans
Fields: deviceId (Ascending), timestamp (Descending)
```

---

## 11. Dependency Injection

All 18 services registered as lazy singletons in `app.dart` / `app.locator.dart`:

| Group | Services |
|-------|----------|
| **URL Engine** | `UrlFeatureExtractor`, `SequentialAnalyzer`, `HostAnalysisService`, `SslAnalysisService`, `ContentAnalysisService`, `MultiModalEngine` |
| **Email Engine** | `EmailParser`, `EmailHeaderAnalyzer`, `EmailContentAnalyzer`, `EmailMultiModalEngine`, `EmailPhishingService` |
| **Core** | `AiService`, `PhishingService`, `FirestoreService`, `DeviceIdService`, `BenchmarkService` |
| **Stacked** | `NavigationService`, `DialogService`, `SnackbarService` |

### Initialization Order

```dart
1. WidgetsFlutterBinding.ensureInitialized()
2. Firebase.initializeApp(options: DefaultFirebaseOptions.currentPlatform)
3. setupLocator()
4. locator<DeviceIdService>().initialize()
5. runApp(const MyApp())
```

---

## 12. Configuration Reference

### AiConfig (`lib/config/ai_config.dart`)

| Constant | Default |
|----------|---------|
| `groqApiKey` | `'YOUR_GROQ_API_KEY_HERE'` |
| `baseUrl` | `'https://api.groq.com/openai/v1/chat/completions'` |
| `model` | `'llama-3.3-70b-versatile'` |
| `timeoutSeconds` | `15` |
| `maxTokens` | `1024` |
| `isConfigured` | Auto-computed from key check |

---

## 13. Error Handling & Graceful Degradation

| Scenario | Behavior |
|----------|----------|
| Firebase not configured | App runs without history. Stream times out in 3s. |
| Groq API key missing | AI skipped. Only multi-modal heuristics shown. |
| Groq API call fails | Error logged. Heuristic results returned. |
| Firestore save fails | Error logged. Result still displayed. |
| SharedPreferences fails | Fallback UUID generated in memory. |
| Invalid URL entered | 100% risk, "Malicious", "Invalid URL format". |
| Network offline | Multi-modal heuristics work fully offline. |
| Individual modality fails | Other modalities still contribute to score. |

---

## 14. Security Considerations

- **API keys:** Use `--dart-define` or backend proxy for production.
- **Firestore rules:** Default test-mode rules are NOT production-ready. Add field validation.
- **Device ID:** Random UUID, no PII. Stored in `localStorage` on web.
- **URL handling:** URLs are analyzed structurally — never visited or fetched.
- **Email content:** Processed client-side only. Not sent to any server (except AI summary to Groq).

---

## 15. Future Roadmap

| Feature | Description |
|---------|-------------|
| Firebase Authentication | Email/Google login with device→user scan migration |
| Real-time phishing feeds | PhishTank / OpenPhish API integration |
| Browser extension | Chrome/Firefox inline URL checking |
| URL screenshot preview | Visual verification via webpage capture |
| Bulk scanning | CSV/text file with multiple URLs |
| Custom trusted domains | User-managed whitelist |
| Export reports | PDF/CSV scan reports |
| Real SSL certificate checking | HTTPS certificate validation via backend |

---

## 16. Troubleshooting

### Firestore "permission-denied" error
Update Firestore rules to allow reads/writes. See [Section 10](#10-firebase-firestore-schema).

### Firestore composite index required
Click the auto-generated link in the browser console to create the `(deviceId, timestamp)` index.

### AI analysis returns null
1. Check `AiConfig.groqApiKey` is not the placeholder.
2. Verify key at [console.groq.com](https://console.groq.com).

### History not showing
1. Verify Firebase is configured (real keys via `flutterfire configure`).
2. Ensure Firestore Database is enabled in Firebase Console.
3. Check that the composite index exists.

### Build errors
```bash
flutter clean && flutter pub get
dart run build_runner build --delete-conflicting-outputs
```

---

<p align="center">
  <em>TrustProbe AI — Multi-Modal AI Phishing Detection Platform</em>
</p>
