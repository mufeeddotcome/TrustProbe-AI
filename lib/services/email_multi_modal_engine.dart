import '../models/email_feature_set.dart';
import '../services/email_parser.dart';
import 'email_header_analyzer.dart';
import 'email_content_analyzer.dart';
import 'multi_modal_engine.dart';

/// EmailMultiModalEngine — Combines email analysis modalities
///
/// Integrates header analysis, content analysis, embedded URL analysis
/// (via the existing URL MultiModalEngine), and metadata analysis
/// into a unified email risk score.
class EmailMultiModalEngine {
  final EmailHeaderAnalyzer _headerAnalyzer;
  final EmailContentAnalyzer _contentAnalyzer;
  final MultiModalEngine _urlEngine;

  /// Modality weights calibrated for email phishing detection
  static const _weights = {
    'header': 0.30,
    'content': 0.25,
    'url': 0.30,
    'metadata': 0.15,
  };

  EmailMultiModalEngine({
    EmailHeaderAnalyzer? headerAnalyzer,
    EmailContentAnalyzer? contentAnalyzer,
    MultiModalEngine? urlEngine,
  }) : _headerAnalyzer = headerAnalyzer ?? EmailHeaderAnalyzer(),
       _contentAnalyzer = contentAnalyzer ?? EmailContentAnalyzer(),
       _urlEngine = urlEngine ?? MultiModalEngine();

  /// Perform multi-modal analysis on a parsed email
  EmailMultiModalResult analyze(ParsedEmail email) {
    // Modality 1: Header analysis
    final headerFeatures = _headerAnalyzer.analyze(email);

    // Modality 2: Content analysis
    final contentFeatures = _contentAnalyzer.analyze(email);

    // Modality 3: Embedded URL analysis (reuse URL engine)
    final urlFeatures = _analyzeEmbeddedUrls(email.embeddedUrls);

    // Modality 4: Metadata analysis
    final metadataFeatures = _analyzeMetadata(email);

    final featureSet = EmailMultiModalFeatureSet(
      headerFeatures: headerFeatures,
      contentFeatures: contentFeatures,
      urlFeatures: urlFeatures,
      metadataFeatures: metadataFeatures,
    );

    // Per-modality risk scores (0-100 for display)
    final modalityScores = {
      'Header Analysis': headerFeatures.riskScore * 100,
      'Content Analysis': contentFeatures.riskScore * 100,
      'URL Analysis': urlFeatures.riskScore * 100,
      'Metadata Analysis': metadataFeatures.riskScore * 100,
    };

    // Calculate combined score
    final combinedScore = _calculateCombinedScore(
      headerFeatures,
      contentFeatures,
      urlFeatures,
      metadataFeatures,
    );

    final riskPercentage = (combinedScore * 100).round().clamp(0, 100);
    final classification = _classify(riskPercentage);

    // Per-modality explanations
    final explanations = {
      'Header Analysis': headerFeatures.riskIndicators.join('. '),
      'Content Analysis': contentFeatures.riskIndicators.join('. '),
      'URL Analysis': urlFeatures.riskIndicators.join('. '),
      'Metadata Analysis': metadataFeatures.riskIndicators.join('. '),
    };
    explanations.removeWhere((_, v) => v.isEmpty);

    // Generate overall reason
    final reason = _generateReason(
      riskPercentage,
      headerFeatures,
      contentFeatures,
      urlFeatures,
      metadataFeatures,
    );

    // Find highest risk URL
    String? highestRiskUrl;
    int? highestRiskUrlScore;
    if (urlFeatures.perUrlScores.isNotEmpty) {
      final maxEntry = urlFeatures.perUrlScores.entries.reduce(
        (a, b) => a.value > b.value ? a : b,
      );
      highestRiskUrl = maxEntry.key;
      highestRiskUrlScore = (maxEntry.value * 100).round();
    }

    return EmailMultiModalResult(
      riskScore: riskPercentage,
      classification: classification,
      reason: reason,
      modalityScores: modalityScores,
      modalityExplanations: explanations,
      featureSet: featureSet,
      highestRiskUrl: highestRiskUrl,
      highestRiskUrlScore: highestRiskUrlScore,
    );
  }

  /// Analyze embedded URLs using the existing URL multi-modal engine
  EmailUrlFeatures _analyzeEmbeddedUrls(List<String> urls) {
    if (urls.isEmpty) {
      return const EmailUrlFeatures(
        urlCount: 0,
        maxUrlRiskScore: 0,
        avgUrlRiskScore: 0,
        mismatchedUrlCount: 0,
        hasUrlShorteners: false,
        hasIpUrls: false,
        hasHighRiskTlds: false,
        perUrlScores: {},
      );
    }

    final perUrlScores = <String, double>{};
    double maxRisk = 0;
    double totalRisk = 0;
    bool hasShorteners = false;
    bool hasIpUrls = false;
    bool hasHighRiskTlds = false;

    for (final url in urls) {
      try {
        var parsedUrl = Uri.tryParse(url);
        if (parsedUrl == null) continue;

        // Ensure scheme
        if (!parsedUrl.hasScheme) {
          parsedUrl = Uri.parse('https://$url');
        }

        final result = _urlEngine.analyze(url, parsedUrl);
        final risk = result.riskScore / 100.0;
        perUrlScores[url] = risk;
        totalRisk += risk;
        if (risk > maxRisk) maxRisk = risk;

        // Check for specific indicators
        if (result.scoreBreakdown['URL Shortener'] != null &&
            result.scoreBreakdown['URL Shortener']! > 0) {
          hasShorteners = true;
        }
        if (result.scoreBreakdown['IP Address Usage'] != null &&
            result.scoreBreakdown['IP Address Usage']! > 0) {
          hasIpUrls = true;
        }
        if (result.scoreBreakdown['Suspicious TLD'] != null &&
            result.scoreBreakdown['Suspicious TLD']! > 0) {
          hasHighRiskTlds = true;
        }
      } catch (_) {
        // Skip malformed URLs
      }
    }

    return EmailUrlFeatures(
      urlCount: urls.length,
      maxUrlRiskScore: maxRisk,
      avgUrlRiskScore: perUrlScores.isNotEmpty
          ? totalRisk / perUrlScores.length
          : 0.0,
      mismatchedUrlCount: 0, // Can't detect from raw text alone
      hasUrlShorteners: hasShorteners,
      hasIpUrls: hasIpUrls,
      hasHighRiskTlds: hasHighRiskTlds,
      perUrlScores: perUrlScores,
    );
  }

  /// Analyze email metadata and formatting
  EmailMetadataFeatures _analyzeMetadata(ParsedEmail email) {
    final body = email.body;

    // HTML complexity
    final htmlTags = RegExp(r'<[a-zA-Z][^>]*>').allMatches(body).length;
    final htmlComplexity = htmlTags > 10
        ? 1.0
        : htmlTags > 5
        ? 0.5
        : htmlTags > 0
        ? 0.2
        : 0.0;

    // Hidden text detection
    final hasHiddenText =
        body.contains('display:none') ||
        body.contains('visibility:hidden') ||
        body.contains('font-size:0') ||
        body.contains('color:#fff') ||
        body.contains('color:white');

    // Tracking pixel detection
    final hasTrackingPixels = RegExp(
      r'<img[^>]*(1x1|width="1"|height="1"|pixel|track)',
      caseSensitive: false,
    ).hasMatch(body);

    // Obfuscation detection
    double obfuscation = 0;
    // Zero-width characters
    if (body.contains('\u200B') ||
        body.contains('\u200C') ||
        body.contains('\u200D') ||
        body.contains('\uFEFF')) {
      obfuscation += 0.4;
    }
    // Encoded characters
    final encodedCount = RegExp(
      r'&#\d+;|&#x[0-9a-fA-F]+;',
    ).allMatches(body).length;
    if (encodedCount > 5) obfuscation += 0.3;
    // Mixed encoding
    if (body.contains('=3D') || body.contains('=20')) obfuscation += 0.3;

    // Suspicious attachment references
    final hasSuspiciousAttachments = RegExp(
      r'\.exe|\.bat|\.cmd|\.scr|\.pif|\.js|\.vbs|\.wsf|\.msi|\.com',
      caseSensitive: false,
    ).hasMatch(body);

    // Length anomaly
    double lengthAnomaly = 0;
    if (body.length < 30 && email.embeddedUrls.isNotEmpty) {
      lengthAnomaly = 0.7; // Very short body with links
    } else if (body.length > 5000) {
      lengthAnomaly = 0.3; // Very long body (obfuscation)
    }

    return EmailMetadataFeatures(
      htmlComplexity: htmlComplexity,
      hasHiddenText: hasHiddenText,
      hasTrackingPixels: hasTrackingPixels,
      obfuscationScore: obfuscation.clamp(0.0, 1.0),
      hasSuspiciousAttachmentRefs: hasSuspiciousAttachments,
      lengthAnomalyScore: lengthAnomaly,
    );
  }

  double _calculateCombinedScore(
    EmailHeaderFeatures header,
    EmailContentFeatures content,
    EmailUrlFeatures url,
    EmailMetadataFeatures metadata,
  ) {
    // Stage 1: Weighted base score
    double score =
        header.riskScore * _weights['header']! +
        content.riskScore * _weights['content']! +
        url.riskScore * _weights['url']! +
        metadata.riskScore * _weights['metadata']!;

    // Stage 2: Critical signal boosting
    // Reply-to mismatch is a VERY strong phishing indicator
    if (header.hasReplyToMismatch) score += 0.25;

    // Brand spoofing
    if (header.brandSpoofScore > 0.5) score += 0.20;

    // Credential requests + urgency = classic phishing combo
    if (content.credentialRequestScore > 0.5 && content.urgencyScore > 0.3) {
      score += 0.25;
    }

    // High-risk embedded URLs
    if (url.maxUrlRiskScore > 0.6) score += 0.15;

    // URL shorteners in email
    if (url.hasUrlShorteners) score += 0.10;

    // Spoofing indicators
    if (header.hasSpoofingIndicators) score += 0.15;

    // Authority impersonation + credential request
    if (content.impersonatesAuthority && content.credentialRequestScore > 0.3) {
      score += 0.15;
    }

    // Suspicious attachments
    if (metadata.hasSuspiciousAttachmentRefs) score += 0.15;

    return score.clamp(0.0, 1.0);
  }

  String _classify(int riskScore) => switch (riskScore) {
    <= 30 => 'Safe',
    <= 60 => 'Suspicious',
    _ => 'Malicious',
  };

  String _generateReason(
    int score,
    EmailHeaderFeatures header,
    EmailContentFeatures content,
    EmailUrlFeatures url,
    EmailMetadataFeatures metadata,
  ) {
    final reasons = <String>[];

    reasons.addAll(header.riskIndicators.take(2));
    reasons.addAll(content.riskIndicators.take(2));
    reasons.addAll(url.riskIndicators.take(1));
    reasons.addAll(metadata.riskIndicators.take(1));

    if (reasons.isEmpty) {
      if (score <= 30) {
        reasons.add('No significant phishing indicators detected in email');
      } else if (score <= 60) {
        reasons.add('Some phishing indicators present in email content');
      } else {
        reasons.add('Multiple high-risk phishing indicators detected');
      }
    }

    return reasons.join('. ');
  }
}

/// Result from email multi-modal analysis
class EmailMultiModalResult {
  final int riskScore;
  final String classification;
  final String reason;
  final Map<String, double> modalityScores;
  final Map<String, String> modalityExplanations;
  final EmailMultiModalFeatureSet featureSet;
  final String? highestRiskUrl;
  final int? highestRiskUrlScore;

  const EmailMultiModalResult({
    required this.riskScore,
    required this.classification,
    required this.reason,
    required this.modalityScores,
    required this.modalityExplanations,
    required this.featureSet,
    this.highestRiskUrl,
    this.highestRiskUrlScore,
  });
}
