/// Email header analysis features
class EmailHeaderFeatures {
  /// Sender domain reputation score (0.0 = safe, 1.0 = high risk)
  final double senderDomainRisk;

  /// Whether sender uses a free email provider (Gmail, Yahoo, etc.)
  final bool isFreeEmailProvider;

  /// Whether reply-to differs from sender (strong phishing indicator)
  final bool hasReplyToMismatch;

  /// Display name impersonation score (0.0 = no, 1.0 = definite)
  final double displayNameImpersonation;

  /// Whether sender domain appears spoofed
  final bool hasSpoofingIndicators;

  /// Whether the sender domain matches a known brand but isn't the real domain
  final double brandSpoofScore;

  /// Detected impersonated brand (if any)
  final String? impersonatedBrand;

  /// Number of suspicious header anomalies
  final int headerAnomalyCount;

  const EmailHeaderFeatures({
    required this.senderDomainRisk,
    required this.isFreeEmailProvider,
    required this.hasReplyToMismatch,
    required this.displayNameImpersonation,
    required this.hasSpoofingIndicators,
    required this.brandSpoofScore,
    this.impersonatedBrand,
    required this.headerAnomalyCount,
  });

  double get riskScore {
    double score = 0;
    double maxScore = 0;

    maxScore += 1.0;
    score += senderDomainRisk;

    maxScore += 0.8;
    score += isFreeEmailProvider ? 0.3 : 0.0;

    maxScore += 1.2;
    score += hasReplyToMismatch ? 1.2 : 0.0;

    maxScore += 1.0;
    score += displayNameImpersonation;

    maxScore += 1.0;
    score += hasSpoofingIndicators ? 1.0 : 0.0;

    maxScore += 1.0;
    score += brandSpoofScore;

    maxScore += 0.5;
    score += (headerAnomalyCount > 3)
        ? 0.5
        : (headerAnomalyCount * 0.15).clamp(0.0, 0.5);

    return (score / maxScore).clamp(0.0, 1.0);
  }

  List<String> get riskIndicators {
    final indicators = <String>[];
    if (senderDomainRisk > 0.6) {
      indicators.add('Sender domain has high risk reputation');
    }
    if (isFreeEmailProvider) {
      indicators.add('Sent from a free email provider');
    }
    if (hasReplyToMismatch) {
      indicators.add(
        'Reply-to address differs from sender (strong phishing indicator)',
      );
    }
    if (displayNameImpersonation > 0.5) {
      indicators.add(
        'Display name may impersonate a known entity${impersonatedBrand != null ? ' ($impersonatedBrand)' : ''}',
      );
    }
    if (hasSpoofingIndicators) {
      indicators.add('Email header contains spoofing indicators');
    }
    if (brandSpoofScore > 0.5) {
      indicators.add('Sender domain mimics a known brand');
    }
    return indicators;
  }

  int get featureCount => 8;
}

/// Email body content analysis features
class EmailContentFeatures {
  /// Urgency language score (0.0 = calm, 1.0 = highly urgent)
  final double urgencyScore;

  /// Number of urgency keywords found
  final int urgencyKeywordCount;

  /// Credential request detection score
  final double credentialRequestScore;

  /// Social engineering tactic score
  final double socialEngineeringScore;

  /// Financial lure detection score
  final double financialLureScore;

  /// Threat/fear language score
  final double threatLanguageScore;

  /// Grammar/spelling anomaly score (poor quality = suspicious)
  final double grammarAnomalyScore;

  /// Whether email impersonates authority (CEO, IT dept, etc.)
  final bool impersonatesAuthority;

  /// Detected urgent/suspicious phrases
  final List<String> suspiciousPhrases;

  const EmailContentFeatures({
    required this.urgencyScore,
    required this.urgencyKeywordCount,
    required this.credentialRequestScore,
    required this.socialEngineeringScore,
    required this.financialLureScore,
    required this.threatLanguageScore,
    required this.grammarAnomalyScore,
    required this.impersonatesAuthority,
    required this.suspiciousPhrases,
  });

  double get riskScore {
    final scores = [
      urgencyScore,
      credentialRequestScore,
      socialEngineeringScore,
      financialLureScore,
      threatLanguageScore,
      grammarAnomalyScore,
      impersonatesAuthority ? 0.8 : 0.0,
    ];
    return (scores.reduce((a, b) => a + b) / scores.length).clamp(0.0, 1.0);
  }

  List<String> get riskIndicators {
    final indicators = <String>[];
    if (urgencyScore > 0.5) {
      indicators.add(
        'High urgency language detected ($urgencyKeywordCount keywords)',
      );
    }
    if (credentialRequestScore > 0.5) {
      indicators.add('Email requests credentials or personal information');
    }
    if (socialEngineeringScore > 0.5) {
      indicators.add('Social engineering tactics detected');
    }
    if (financialLureScore > 0.5) {
      indicators.add('Financial lure or reward language present');
    }
    if (threatLanguageScore > 0.5) {
      indicators.add('Threatening or fear-inducing language detected');
    }
    if (grammarAnomalyScore > 0.5) {
      indicators.add('Poor grammar or unusual formatting detected');
    }
    if (impersonatesAuthority) {
      indicators.add('Email impersonates an authority figure');
    }
    if (suspiciousPhrases.isNotEmpty) {
      indicators.add(
        'Suspicious phrases: ${suspiciousPhrases.take(3).join(", ")}',
      );
    }
    return indicators;
  }

  int get featureCount => 9;
}

/// Email embedded URL analysis features
class EmailUrlFeatures {
  /// Number of URLs found in email body
  final int urlCount;

  /// Maximum risk score among embedded URLs
  final double maxUrlRiskScore;

  /// Average risk score across all URLs
  final double avgUrlRiskScore;

  /// Number of URLs with mismatched display text vs actual URL
  final int mismatchedUrlCount;

  /// Whether any URL uses a URL shortener
  final bool hasUrlShorteners;

  /// Whether any URL points to an IP address
  final bool hasIpUrls;

  /// Whether URLs use high-risk TLDs
  final bool hasHighRiskTlds;

  /// Per-URL analysis results (URL → risk score)
  final Map<String, double> perUrlScores;

  const EmailUrlFeatures({
    required this.urlCount,
    required this.maxUrlRiskScore,
    required this.avgUrlRiskScore,
    required this.mismatchedUrlCount,
    required this.hasUrlShorteners,
    required this.hasIpUrls,
    required this.hasHighRiskTlds,
    required this.perUrlScores,
  });

  double get riskScore {
    if (urlCount == 0) return 0.0;

    double score = 0;
    double maxScore = 0;

    maxScore += 1.0;
    score += maxUrlRiskScore;

    maxScore += 0.8;
    score += avgUrlRiskScore * 0.8;

    maxScore += 0.8;
    score += (mismatchedUrlCount > 0) ? 0.8 : 0.0;

    maxScore += 0.6;
    score += hasUrlShorteners ? 0.6 : 0.0;

    maxScore += 0.8;
    score += hasIpUrls ? 0.8 : 0.0;

    maxScore += 0.6;
    score += hasHighRiskTlds ? 0.6 : 0.0;

    return (score / maxScore).clamp(0.0, 1.0);
  }

  List<String> get riskIndicators {
    final indicators = <String>[];
    if (urlCount == 0) {
      indicators.add('No URLs found in email body');
      return indicators;
    }
    if (maxUrlRiskScore > 0.6) {
      indicators.add(
        'High-risk URL detected (${(maxUrlRiskScore * 100).toStringAsFixed(0)}% risk)',
      );
    }
    if (mismatchedUrlCount > 0) {
      indicators.add('$mismatchedUrlCount URL(s) with mismatched display text');
    }
    if (hasUrlShorteners) indicators.add('URL shortener links detected');
    if (hasIpUrls) indicators.add('URLs pointing to IP addresses detected');
    if (hasHighRiskTlds) indicators.add('URLs with high-risk TLDs detected');
    indicators.add('$urlCount URL(s) analyzed in email body');
    return indicators;
  }

  int get featureCount => 8;
}

/// Email metadata and formatting features
class EmailMetadataFeatures {
  /// HTML complexity score (heavily formatted = potentially suspicious)
  final double htmlComplexity;

  /// Whether email contains hidden/invisible text
  final bool hasHiddenText;

  /// Whether email uses external image tracking pixels
  final bool hasTrackingPixels;

  /// Obfuscation score (encoded chars, zero-width chars, etc.)
  final double obfuscationScore;

  /// Whether email has suspicious attachment references
  final bool hasSuspiciousAttachmentRefs;

  /// Body length anomaly (very short or very long)
  final double lengthAnomalyScore;

  const EmailMetadataFeatures({
    required this.htmlComplexity,
    required this.hasHiddenText,
    required this.hasTrackingPixels,
    required this.obfuscationScore,
    required this.hasSuspiciousAttachmentRefs,
    required this.lengthAnomalyScore,
  });

  double get riskScore {
    double score = 0;
    double maxScore = 0;

    maxScore += 0.6;
    score += htmlComplexity * 0.6;

    maxScore += 0.7;
    score += hasHiddenText ? 0.7 : 0.0;

    maxScore += 0.5;
    score += hasTrackingPixels ? 0.5 : 0.0;

    maxScore += 0.8;
    score += obfuscationScore * 0.8;

    maxScore += 0.7;
    score += hasSuspiciousAttachmentRefs ? 0.7 : 0.0;

    maxScore += 0.4;
    score += lengthAnomalyScore * 0.4;

    return (score / maxScore).clamp(0.0, 1.0);
  }

  List<String> get riskIndicators {
    final indicators = <String>[];
    if (htmlComplexity > 0.6) {
      indicators.add('Highly complex HTML formatting detected');
    }
    if (hasHiddenText) {
      indicators.add('Hidden or invisible text detected');
    }
    if (hasTrackingPixels) {
      indicators.add('Email tracking pixels detected');
    }
    if (obfuscationScore > 0.5) {
      indicators.add('Text obfuscation techniques detected');
    }
    if (hasSuspiciousAttachmentRefs) {
      indicators.add('Suspicious attachment references found');
    }
    if (lengthAnomalyScore > 0.6) {
      indicators.add('Unusual email body length');
    }
    return indicators;
  }

  int get featureCount => 6;
}

/// Combined email multi-modal feature set
class EmailMultiModalFeatureSet {
  final EmailHeaderFeatures headerFeatures;
  final EmailContentFeatures contentFeatures;
  final EmailUrlFeatures urlFeatures;
  final EmailMetadataFeatures metadataFeatures;

  const EmailMultiModalFeatureSet({
    required this.headerFeatures,
    required this.contentFeatures,
    required this.urlFeatures,
    required this.metadataFeatures,
  });

  int get totalFeatureCount =>
      headerFeatures.featureCount +
      contentFeatures.featureCount +
      urlFeatures.featureCount +
      metadataFeatures.featureCount;
}
