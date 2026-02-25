<p align="center">
  <img src="https://img.shields.io/badge/Flutter-3.10+-02569B?style=for-the-badge&logo=flutter" alt="Flutter 3.10+"/>
  <img src="https://img.shields.io/badge/Dart-3.0+-0175C2?style=for-the-badge&logo=dart" alt="Dart 3.0+"/>
  <img src="https://img.shields.io/badge/AI-Llama%203.3%2070B-FF6F00?style=for-the-badge" alt="Llama 3.3"/>
  <img src="https://img.shields.io/badge/Firebase-Firestore-FFCA28?style=for-the-badge&logo=firebase" alt="Firebase"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License"/>
</p>

<h1 align="center">🛡️ TrustProbe AI</h1>

<p align="center">
  <strong>Multi-Modal AI Phishing Detection Platform</strong><br/>
  <em>Research-grade URL & email analysis with 55+ features across 5 detection modalities</em>
</p>

<p align="center">
  <a href="https://akshaychandt.github.io/TrustProbe-AI/">🌐 Live Demo</a> •
  <a href="DOCUMENTATION.md">📖 Full Documentation</a> •
  <a href="#-quick-start">🚀 Quick Start</a>
</p>

---

## ✨ Features

### URL Analysis

| Feature | Description |
|---------|-------------|
| 🧠 **Multi-Modal Detection** | 5-modality engine: CNN-equivalent URL features, LSTM-equivalent sequential patterns, host/domain analysis, SSL/security checks, content analysis |
| 🤖 **AI Threat Narrative** | Llama 3.3 70B (open-source) via Groq API provides context-aware threat summaries with per-modality reasoning |
| 📊 **55+ Feature Extraction** | Character entropy, bigram analysis, TLD reputation scores, brand impersonation confidence, domain age heuristics, and more |
| 🏷️ **Smart Classification** | Safe / Suspicious / Malicious with transparent per-modality score breakdown |
| 📝 **Human-Readable Explanations** | Detailed reasoning referencing CNN, LSTM, and host analysis findings |
| 📈 **Benchmark Suite** | 170+ URL dataset (PhishTank, OpenPhish, Alexa Top Sites) with accuracy, precision, recall, F1 metrics |

### Email Analysis

| Feature | Description |
|---------|-------------|
| 📧 **Email Phishing Detection** | Multi-modal email analysis with header, content, embedded URL, and metadata modalities |
| 🔍 **Header Analysis** | Sender domain reputation, reply-to mismatch, display name impersonation, spoofing detection |
| 📝 **Content Analysis** | Urgency language detection, credential requests, social engineering, financial lures, threat language |
| 🔗 **Embedded URL Scanning** | Every link in an email is analyzed through the full URL multi-modal engine |

### Platform

| Feature | Description |
|---------|-------------|
| 📚 **Per-Device History** | Scan history stored in Firebase Firestore, scoped by anonymous device ID |
| 🎨 **Modern UI/UX** | Dark theme with glassmorphism, gradient backgrounds, smooth animations |
| 📱 **Fully Responsive** | Optimized for desktop, tablet, and mobile |

---

## 🏗️ Architecture

TrustProbe AI follows **Stacked MVVM** with a multi-modal service architecture:

```
+------------------------------------------------------------------+
|                           UI Layer                                |
|  +-----------+ +------------+ +--------------+ +----------------+ |
|  | HomeView  | | ResultCard | | HistoryTable | | EmailResult    | |
|  +-----+-----+ +-----+------+ +------+------+ +-------+--------+ |
|        |              |               |                |          |
+--------+--------------+---------------+----------------+----------+
|                       ViewModel Layer                             |
|                  +--------------------+                           |
|                  |   HomeViewModel    |                           |
|                  +--------+-----------+                           |
|                           |                                       |
+---------------------------+---------------------------------------+
|                        Service Layer                              |
|  +------------------+  +-------------------+  +-----------------+ |
|  | PhishingService  |  | EmailPhishingSvc  |  | BenchmarkSvc    | |
|  +--------+---------+  +--------+----------+  +-------+---------+ |
|           |                      |                     |          |
|  +--------v---------+  +--------v----------+           |          |
|  | MultiModalEngine |  | EmailMultiModal   |           |          |
|  |  (URL Analysis)  |  |  (Email Analysis) |           |          |
|  +--+--+--+--+--+---+  +--+--+--+--+------+           |          |
|     |  |  |  |  |          |  |  |  |                  |          |
|     v  v  v  v  v          v  v  v  v                  |          |
|  [URL] [Seq] [Host]    [Header] [Content]              |          |
|  [SSL] [Content]       [URL]    [Metadata]             |          |
|                                                        |          |
|  +-----------+  +----------+  +-----------+            |          |
|  | AiService |  | Firestore|  | DeviceId  |            |          |
|  |(Llama 3.3)|  |  Service |  |  Service  |            |          |
|  +-----------+  +----------+  +-----------+            |          |
+------------------------------------------------------------------+
```

### Layer Responsibilities

| Layer | Component | Responsibility |
|-------|-----------|----------------|
| **View** | `HomeView`, `ResultCard`, `EmailResultCard`, `SearchHistoryTable` | Pure UI rendering — no business logic |
| **ViewModel** | `HomeViewModel` | State management, orchestrates URL and email services |
| **Service** | `PhishingService` → `MultiModalEngine` | URL phishing detection via 5-modality engine |
| **Service** | `EmailPhishingService` → `EmailMultiModalEngine` | Email phishing detection via 4-modality engine |
| **Service** | `UrlFeatureExtractor` | CNN-equivalent: 25+ character-level URL features |
| **Service** | `SequentialAnalyzer` | LSTM-equivalent: 8 sequential pattern features |
| **Service** | `HostAnalysisService` | Domain reputation, brand impersonation, TLD scoring |
| **Service** | `SslAnalysisService` | HTTPS, certificate, redirect, mixed content checks |
| **Service** | `ContentAnalysisService` | Login page, download, data exfiltration detection |
| **Service** | `EmailParser` | Email header/body parsing, URL extraction |
| **Service** | `EmailHeaderAnalyzer` | Sender reputation, spoofing, display name impersonation |
| **Service** | `EmailContentAnalyzer` | Urgency, credential requests, social engineering detection |
| **Service** | `BenchmarkService` | Accuracy evaluation against PhishTank/OpenPhish/Alexa |
| **Service** | `AiService` | LLM integration via Groq API (Llama 3.3 70B) |
| **Service** | `FirestoreService` | Firestore CRUD for scan history (device-scoped) |
| **Service** | `DeviceIdService` | Anonymous device identification via persistent UUID |
| **Model** | `ScanResult`, `EmailScanResult` | Scan result data structures with serialization |
| **Model** | `MultiModalFeatureSet`, `EmailMultiModalFeatureSet` | Multi-modal feature containers |
| **Data** | `PhishingDataset` | 170+ URL evaluation dataset |
| **Config** | `AiConfig` | Centralized AI/API configuration |

---

## 📁 Project Structure

```
lib/
├── app/
│   ├── app.dart                         # Stacked app config (routes + DI)
│   ├── app.locator.dart                 # Service locator (auto-generated)
│   └── app.router.dart                  # Routes (auto-generated)
│
├── config/
│   └── ai_config.dart                   # Groq API configuration
│
├── data/
│   └── phishing_dataset.dart            # 170+ URL benchmark dataset
│
├── models/
│   ├── scan_result.dart                 # URL scan result model
│   ├── email_scan_result.dart           # Email scan result model
│   ├── feature_set.dart                 # URL feature classes (745 lines)
│   └── email_feature_set.dart           # Email feature classes (376 lines)
│
├── services/
│   ├── # URL Multi-Modal Engine
│   ├── url_feature_extractor.dart       # CNN-equiv: 25+ URL features
│   ├── sequential_analyzer.dart         # LSTM-equiv: 8 sequential features
│   ├── host_analysis_service.dart       # Host/domain: 10 features
│   ├── ssl_analysis_service.dart        # SSL/security: 5 features
│   ├── content_analysis_service.dart    # Content: 7 features
│   ├── multi_modal_engine.dart          # Combines 5 URL modalities
│   │
│   ├── # Email Multi-Modal Engine
│   ├── email_parser.dart                # Email header/body parser
│   ├── email_header_analyzer.dart       # Sender reputation, spoofing
│   ├── email_content_analyzer.dart      # NLP: urgency, credential requests
│   ├── email_multi_modal_engine.dart    # Combines 4 email modalities
│   ├── email_phishing_service.dart      # Email analysis orchestrator
│   │
│   ├── # Core Services
│   ├── ai_service.dart                  # Llama 3.3 70B via Groq API
│   ├── phishing_service.dart            # URL analysis orchestrator
│   ├── firestore_service.dart           # Firebase Firestore (device-scoped)
│   ├── device_id_service.dart           # Anonymous device ID
│   └── benchmark_service.dart           # Accuracy evaluation
│
├── ui/
│   ├── views/home/
│   │   ├── home_view.dart               # Main screen
│   │   └── home_viewmodel.dart          # URL + email state management
│   └── widgets/
│       ├── result_card.dart             # URL analysis result card
│       ├── email_result_card.dart       # Email analysis result card
│       └── search_history_table.dart    # Scan history table
│
├── firebase_options.dart                # Firebase config (auto-generated)
└── main.dart                            # App entry point
```

---

## 🔬 Detection Engine

### URL Multi-Modal Analysis (55+ features)

| Modality | Service | Features | Weight | Analogous ML |
|----------|---------|----------|--------|--------------|
| **URL Lexical** | `UrlFeatureExtractor` | 25+ (entropy, char distributions, n-grams, digit ratio, path depth, etc.) | 25% | CNN |
| **Sequential Patterns** | `SequentialAnalyzer` | 8 (char transitions, bigram frequencies, positional distribution, randomness) | 20% | LSTM |
| **Host/Domain** | `HostAnalysisService` | 10 (TLD risk scores, brand impersonation, domain age, randomness, shorteners) | 25% | Feature Engineering |
| **SSL/Security** | `SslAnalysisService` | 5 (HTTPS, free SSL indicators, redirect patterns, mixed content) | 15% | Feature Engineering |
| **Content** | `ContentAnalysisService` | 7 (login page, credential harvesting, data exfiltration, service mimicry) | 15% | NLP |

### Email Multi-Modal Analysis (30+ features)

| Modality | Service | Features | Weight |
|----------|---------|----------|--------|
| **Header** | `EmailHeaderAnalyzer` | 8 (sender domain risk, display name impersonation, spoofing, reply-to mismatch) | 30% |
| **Content** | `EmailContentAnalyzer` | 9 (urgency, credential requests, social engineering, financial lures, threats, grammar) | 30% |
| **Embedded URLs** | `MultiModalEngine` (reused) | 55+ (full URL analysis for each embedded link) | 25% |
| **Metadata** | `EmailMultiModalEngine` | 5 (HTML ratio, link density, external resource patterns) | 15% |

### Classification Thresholds

| Score Range | Classification |
|-------------|---------------|
| 0 – 40 | ✅ Safe |
| 41 – 70 | ⚠️ Suspicious |
| 71 – 100 | 🚨 Malicious |

### Benchmark Dataset

| Source | Count | Type |
|--------|-------|------|
| PhishTank | ~50 | Phishing URLs |
| OpenPhish | ~40 | Phishing URLs |
| Alexa Top Sites | ~80 | Safe URLs |
| **Total** | **170+** | Balanced evaluation set |

Benchmark metrics: **Accuracy**, **Precision**, **Recall**, **F1 Score**, with per-source breakdown.

---

## 🛠️ Tech Stack

| Category | Technology | Purpose |
|----------|-----------|---------|
| **Framework** | Flutter Web | Cross-platform UI |
| **Language** | Dart 3.10+ | Type-safe development |
| **Architecture** | Stacked MVVM | State management & DI |
| **AI Model** | Llama 3.3 70B (open-source) | Intelligent threat analysis |
| **AI Provider** | Groq API | Ultra-fast LLM inference |
| **Database** | Cloud Firestore | Real-time per-device scan history |
| **Firebase** | Firebase Core | Backend infrastructure |
| **Device Identity** | shared_preferences + uuid | Anonymous device tracking |
| **Typography** | Google Fonts (Poppins, Inter) | Modern UI typography |
| **Design System** | Material Design 3 | UI components |
| **HTTP Client** | `package:http` | API communication |
| **Testing** | `flutter_test` | Unit & widget tests |

---

## 🚀 Quick Start

### Prerequisites

- Flutter 3.10+
- Dart 3.0+
- Firebase project (for scan history)
- Groq API key (for AI analysis — optional)

### Setup

```bash
# Clone the repository
git clone https://github.com/akshaychandt/TrustProbe-AI.git
cd TrustProbe-AI

# Install dependencies
flutter pub get

# Configure Firebase
flutterfire configure

# (Optional) Set Groq API key in lib/config/ai_config.dart
# Replace 'YOUR_GROQ_API_KEY_HERE' with your key from console.groq.com

# Run the app
flutter run -d chrome
```

### Firebase Setup

1. Create a project at [Firebase Console](https://console.firebase.google.com)
2. Enable **Firestore Database** → Start in test mode
3. Run `flutterfire configure` to generate `firebase_options.dart`
4. On first query, Firestore will prompt for a composite index on `(deviceId, timestamp)` — click the link to create it

### Verify Everything

```bash
# Analyze a URL
# Enter "https://google.com" → Should show "Safe"
# Enter "http://paypal-login.tk/verify" → Should show "Malicious"

# Check Firestore
# Firebase Console → Firestore → url_scans collection should populate
```

---

## 🔒 Security

### Firestore Rules (Test Mode)

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /url_scans/{document=**} {
      allow read: if true;
      allow write: if request.resource.data.keys()
        .hasAll(['url', 'riskScore', 'classification', 'deviceId']);
    }
  }
}
```

### API Key Security

- **Groq API key** is in `ai_config.dart` — for production, use `--dart-define` or a backend proxy
- **Firebase config** is auto-generated by `flutterfire configure` — safe to commit

---

## 📖 Documentation

For comprehensive technical documentation covering architecture, algorithms, service APIs, feature specifications, error handling, and extensibility, see **[DOCUMENTATION.md](DOCUMENTATION.md)**.

---

## 📝 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>TrustProbe AI</strong> — Built with Flutter 💙, Llama 3.3 🦙, and multi-modal intelligence 🧠
</p>
