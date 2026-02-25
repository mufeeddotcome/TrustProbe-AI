import 'dart:math';

/// URL lexical features — CNN-equivalent character-level analysis
///
/// Extracts 25+ numeric features from the URL string that a
/// character-level CNN would learn during training.
class UrlFeatures {
  /// Shannon entropy of the URL string (higher = more random/suspicious)
  final double entropy;

  /// Total URL length
  final int urlLength;

  /// Domain name length
  final int domainLength;

  /// Path component length
  final int pathLength;

  /// Number of dots in the URL
  final int dotCount;

  /// Number of dashes in the URL
  final int dashCount;

  /// Number of underscores in the URL
  final int underscoreCount;

  /// Number of digits in the URL
  final int digitCount;

  /// Ratio of digits to total characters
  final double digitRatio;

  /// Number of special characters (!@#$%^&*()=+[]{}|;:'",<>?/)
  final int specialCharCount;

  /// Ratio of special chars to total characters
  final double specialCharRatio;

  /// Number of uppercase characters in the original URL
  final int uppercaseCount;

  /// Ratio of uppercase to alpha characters
  final double uppercaseRatio;

  /// Path depth (number of / separated segments)
  final int pathDepth;

  /// Number of query parameters
  final int queryParamCount;

  /// Whether URL has a fragment (#)
  final bool hasFragment;

  /// Whether URL has a port number
  final bool hasPort;

  /// Whether URL uses a non-standard port
  final bool hasNonStandardPort;

  /// Longest consecutive consonant run (indicator of random strings)
  final int longestConsonantRun;

  /// Number of repeated character sequences
  final int repeatedCharSequences;

  /// Vowel to consonant ratio
  final double vowelConsonantRatio;

  /// Character variety (unique chars / total chars)
  final double charVariety;

  /// Average word length in domain
  final double avgWordLengthInDomain;

  /// Number of subdomains
  final int subdomainCount;

  /// Whether the domain contains only hex characters (potential IP encoding)
  final bool domainIsHexLike;

  /// Number of @ symbols
  final int atSymbolCount;

  const UrlFeatures({
    required this.entropy,
    required this.urlLength,
    required this.domainLength,
    required this.pathLength,
    required this.dotCount,
    required this.dashCount,
    required this.underscoreCount,
    required this.digitCount,
    required this.digitRatio,
    required this.specialCharCount,
    required this.specialCharRatio,
    required this.uppercaseCount,
    required this.uppercaseRatio,
    required this.pathDepth,
    required this.queryParamCount,
    required this.hasFragment,
    required this.hasPort,
    required this.hasNonStandardPort,
    required this.longestConsonantRun,
    required this.repeatedCharSequences,
    required this.vowelConsonantRatio,
    required this.charVariety,
    required this.avgWordLengthInDomain,
    required this.subdomainCount,
    required this.domainIsHexLike,
    required this.atSymbolCount,
  });

  /// Calculate a normalized risk score (0.0 - 1.0)
  double get riskScore {
    double score = 0;
    double maxScore = 0;

    // Entropy: normal URLs ~3.5-4.0, phishing ~4.5+
    maxScore += 1.0;
    score += (entropy > 4.5)
        ? 1.0
        : (entropy > 4.0)
        ? 0.5
        : 0.0;

    // URL length: phishing URLs tend to be longer
    maxScore += 1.0;
    score += (urlLength > 75)
        ? 1.0
        : (urlLength > 54)
        ? 0.5
        : 0.0;

    // Domain length
    maxScore += 1.0;
    score += (domainLength > 30)
        ? 1.0
        : (domainLength > 20)
        ? 0.4
        : 0.0;

    // Digit ratio: high digit ratio = suspicious
    maxScore += 1.0;
    score += (digitRatio > 0.3)
        ? 1.0
        : (digitRatio > 0.15)
        ? 0.5
        : 0.0;

    // Special char ratio
    maxScore += 1.0;
    score += (specialCharRatio > 0.2)
        ? 1.0
        : (specialCharRatio > 0.1)
        ? 0.5
        : 0.0;

    // Path depth
    maxScore += 0.8;
    score += (pathDepth > 5)
        ? 0.8
        : (pathDepth > 3)
        ? 0.3
        : 0.0;

    // Query params
    maxScore += 0.6;
    score += (queryParamCount > 3)
        ? 0.6
        : (queryParamCount > 1)
        ? 0.2
        : 0.0;

    // Consonant runs (random strings)
    maxScore += 1.0;
    score += (longestConsonantRun > 6)
        ? 1.0
        : (longestConsonantRun > 4)
        ? 0.4
        : 0.0;

    // Character variety
    maxScore += 0.8;
    score += (charVariety < 0.3)
        ? 0.8
        : (charVariety > 0.85)
        ? 0.5
        : 0.0;

    // Subdomains
    maxScore += 0.8;
    score += (subdomainCount > 3)
        ? 0.8
        : (subdomainCount > 2)
        ? 0.4
        : 0.0;

    // Port
    maxScore += 0.8;
    score += hasNonStandardPort ? 0.8 : 0.0;

    // At symbol
    maxScore += 1.0;
    score += (atSymbolCount > 0) ? 1.0 : 0.0;

    // Hex-like domain
    maxScore += 0.8;
    score += domainIsHexLike ? 0.8 : 0.0;

    return (score / maxScore).clamp(0.0, 1.0);
  }

  /// Get human-readable explanation of risky features
  List<String> get riskIndicators {
    final indicators = <String>[];
    if (entropy > 4.5) {
      indicators.add(
        'High character entropy (${entropy.toStringAsFixed(2)}) suggests randomized/obfuscated URL',
      );
    }
    if (urlLength > 75) {
      indicators.add('Unusually long URL ($urlLength characters)');
    }
    if (domainLength > 30) {
      indicators.add('Long domain name ($domainLength characters)');
    }
    if (digitRatio > 0.3) {
      indicators.add(
        'High digit ratio (${(digitRatio * 100).toStringAsFixed(0)}%) in URL',
      );
    }
    if (specialCharRatio > 0.2) {
      indicators.add(
        'Excessive special characters (${(specialCharRatio * 100).toStringAsFixed(0)}%)',
      );
    }
    if (longestConsonantRun > 6) {
      indicators.add(
        'Random character sequences detected (run of $longestConsonantRun consonants)',
      );
    }
    if (subdomainCount > 3) {
      indicators.add(
        'Complex subdomain structure ($subdomainCount subdomains)',
      );
    }
    if (hasNonStandardPort) indicators.add('Non-standard port detected');
    if (atSymbolCount > 0) {
      indicators.add('URL contains @ symbol (potential obfuscation)');
    }
    if (domainIsHexLike) {
      indicators.add(
        'Domain contains hex-like patterns (potential IP encoding)',
      );
    }
    if (pathDepth > 5) {
      indicators.add('Deep path structure ($pathDepth levels)');
    }
    return indicators;
  }

  int get featureCount => 25;

  Map<String, dynamic> toMap() => {
    'entropy': entropy,
    'urlLength': urlLength,
    'domainLength': domainLength,
    'pathLength': pathLength,
    'dotCount': dotCount,
    'dashCount': dashCount,
    'underscoreCount': underscoreCount,
    'digitCount': digitCount,
    'digitRatio': digitRatio,
    'specialCharCount': specialCharCount,
    'specialCharRatio': specialCharRatio,
    'uppercaseCount': uppercaseCount,
    'uppercaseRatio': uppercaseRatio,
    'pathDepth': pathDepth,
    'queryParamCount': queryParamCount,
    'hasFragment': hasFragment,
    'hasPort': hasPort,
    'hasNonStandardPort': hasNonStandardPort,
    'longestConsonantRun': longestConsonantRun,
    'repeatedCharSequences': repeatedCharSequences,
    'vowelConsonantRatio': vowelConsonantRatio,
    'charVariety': charVariety,
    'avgWordLengthInDomain': avgWordLengthInDomain,
    'subdomainCount': subdomainCount,
    'domainIsHexLike': domainIsHexLike,
    'atSymbolCount': atSymbolCount,
  };
}

/// Sequential pattern features — LSTM-equivalent analysis
///
/// Analyzes character sequences and transitions that a Long Short-Term
/// Memory network would learn during training.
class SequentialFeatures {
  /// Character type transition anomaly score (0.0 = normal, 1.0 = highly anomalous)
  final double transitionAnomalyScore;

  /// Token sequence anomaly score
  final double tokenAnomalyScore;

  /// Positional distribution anomaly score
  final double positionalAnomalyScore;

  /// Bigram anomaly score (unusual character pairs)
  final double bigramAnomalyScore;

  /// Direction changes in character types (letter->digit->letter = 2 changes)
  final int typeDirectionChanges;

  /// Maximum token length anomaly (very long tokens are suspicious)
  final double maxTokenLengthRatio;

  /// Number of anomalous subsequences detected
  final int anomalousSubsequences;

  /// Ratio of random-looking segments to total segments
  final double randomSegmentRatio;

  const SequentialFeatures({
    required this.transitionAnomalyScore,
    required this.tokenAnomalyScore,
    required this.positionalAnomalyScore,
    required this.bigramAnomalyScore,
    required this.typeDirectionChanges,
    required this.maxTokenLengthRatio,
    required this.anomalousSubsequences,
    required this.randomSegmentRatio,
  });

  /// Calculate a normalized risk score (0.0 - 1.0)
  double get riskScore {
    final scores = [
      transitionAnomalyScore,
      tokenAnomalyScore,
      positionalAnomalyScore,
      bigramAnomalyScore,
      (typeDirectionChanges > 10)
          ? 1.0
          : (typeDirectionChanges / 10.0).clamp(0.0, 1.0),
      maxTokenLengthRatio.clamp(0.0, 1.0),
      (anomalousSubsequences > 5)
          ? 1.0
          : (anomalousSubsequences / 5.0).clamp(0.0, 1.0),
      randomSegmentRatio,
    ];
    return (scores.reduce((a, b) => a + b) / scores.length).clamp(0.0, 1.0);
  }

  List<String> get riskIndicators {
    final indicators = <String>[];
    if (transitionAnomalyScore > 0.6) {
      indicators.add(
        'Unusual character type transitions detected (score: ${transitionAnomalyScore.toStringAsFixed(2)})',
      );
    }
    if (tokenAnomalyScore > 0.6) {
      indicators.add(
        'Suspicious token patterns in URL structure (score: ${tokenAnomalyScore.toStringAsFixed(2)})',
      );
    }
    if (bigramAnomalyScore > 0.5) {
      indicators.add(
        'Anomalous character pair frequencies (bigram score: ${bigramAnomalyScore.toStringAsFixed(2)})',
      );
    }
    if (typeDirectionChanges > 8) {
      indicators.add(
        'Frequent character type alternation ($typeDirectionChanges changes)',
      );
    }
    if (randomSegmentRatio > 0.4) {
      indicators.add(
        'Random-looking URL segments detected (${(randomSegmentRatio * 100).toStringAsFixed(0)}%)',
      );
    }
    if (anomalousSubsequences > 3) {
      indicators.add(
        '$anomalousSubsequences anomalous subsequences identified',
      );
    }
    return indicators;
  }

  int get featureCount => 8;

  Map<String, dynamic> toMap() => {
    'transitionAnomalyScore': transitionAnomalyScore,
    'tokenAnomalyScore': tokenAnomalyScore,
    'positionalAnomalyScore': positionalAnomalyScore,
    'bigramAnomalyScore': bigramAnomalyScore,
    'typeDirectionChanges': typeDirectionChanges,
    'maxTokenLengthRatio': maxTokenLengthRatio,
    'anomalousSubsequences': anomalousSubsequences,
    'randomSegmentRatio': randomSegmentRatio,
  };
}

/// Host and domain attribute features
class HostFeatures {
  /// TLD reputation score (0.0 = safe, 1.0 = high risk)
  final double tldRiskScore;

  /// Domain structure risk score
  final double domainStructureRisk;

  /// Brand impersonation confidence (0.0 = no, 1.0 = definite)
  final double brandImpersonationScore;

  /// Whether domain is an IP address
  final bool isIpAddress;

  /// Whether domain uses a known URL shortener
  final bool isUrlShortener;

  /// Subdomain depth
  final int subdomainDepth;

  /// Domain randomness score (0.0 = normal, 1.0 = random-looking)
  final double domainRandomnessScore;

  /// Detected brand name (if brand impersonation)
  final String? impersonatedBrand;

  /// Whether it matches a trusted/known domain exactly
  final bool isTrustedDomain;

  /// Domain age risk (heuristic: new-looking domains score higher)
  final double domainAgeRisk;

  const HostFeatures({
    required this.tldRiskScore,
    required this.domainStructureRisk,
    required this.brandImpersonationScore,
    required this.isIpAddress,
    required this.isUrlShortener,
    required this.subdomainDepth,
    required this.domainRandomnessScore,
    this.impersonatedBrand,
    required this.isTrustedDomain,
    required this.domainAgeRisk,
  });

  double get riskScore {
    if (isTrustedDomain) return 0.0;

    double score = 0;
    double maxScore = 0;

    maxScore += 1.0;
    score += tldRiskScore;

    maxScore += 1.0;
    score += domainStructureRisk;

    maxScore += 1.5;
    score += brandImpersonationScore * 1.5;

    maxScore += 1.2;
    score += isIpAddress ? 1.2 : 0.0;

    maxScore += 0.8;
    score += isUrlShortener ? 0.8 : 0.0;

    maxScore += 1.0;
    score += domainRandomnessScore;

    maxScore += 0.8;
    score += domainAgeRisk * 0.8;

    maxScore += 0.7;
    score += (subdomainDepth > 3)
        ? 0.7
        : (subdomainDepth > 2)
        ? 0.3
        : 0.0;

    return (score / maxScore).clamp(0.0, 1.0);
  }

  List<String> get riskIndicators {
    final indicators = <String>[];
    if (isTrustedDomain) {
      indicators.add('Recognized as a trusted domain');
      return indicators;
    }
    if (tldRiskScore > 0.6) {
      indicators.add('High-risk top-level domain detected');
    }
    if (brandImpersonationScore > 0.5) {
      indicators.add(
        'Possible brand impersonation${impersonatedBrand != null ? ' of "$impersonatedBrand"' : ''}',
      );
    }
    if (isIpAddress) indicators.add('Domain is a raw IP address');
    if (isUrlShortener) indicators.add('URL shortener detected');
    if (domainRandomnessScore > 0.6) {
      indicators.add('Domain name appears randomly generated');
    }
    if (domainAgeRisk > 0.6) {
      indicators.add(
        'Domain characteristics suggest a newly registered domain',
      );
    }
    if (subdomainDepth > 3) {
      indicators.add('Excessive subdomain complexity ($subdomainDepth levels)');
    }
    return indicators;
  }

  int get featureCount => 10;

  Map<String, dynamic> toMap() => {
    'tldRiskScore': tldRiskScore,
    'domainStructureRisk': domainStructureRisk,
    'brandImpersonationScore': brandImpersonationScore,
    'isIpAddress': isIpAddress,
    'isUrlShortener': isUrlShortener,
    'subdomainDepth': subdomainDepth,
    'domainRandomnessScore': domainRandomnessScore,
    'impersonatedBrand': impersonatedBrand,
    'isTrustedDomain': isTrustedDomain,
    'domainAgeRisk': domainAgeRisk,
  };
}

/// SSL and security attribute features
class SslFeatures {
  /// Whether HTTPS is used
  final bool isHttps;

  /// Whether domain is associated with free SSL providers (heuristic)
  final bool hasFreeSSLIndicators;

  /// Security score (0.0 = insecure, 1.0 = secure)
  final double securityScore;

  /// Mixed content risk indicators in URL
  final bool hasMixedContentIndicators;

  /// Whether URL contains security-related redirect patterns
  final bool hasRedirectPatterns;

  const SslFeatures({
    required this.isHttps,
    required this.hasFreeSSLIndicators,
    required this.securityScore,
    required this.hasMixedContentIndicators,
    required this.hasRedirectPatterns,
  });

  /// Risk score (inverted — lower security = higher risk)
  double get riskScore {
    double risk = 0;
    double maxRisk = 0;

    maxRisk += 1.0;
    risk += isHttps ? 0.0 : 1.0;

    maxRisk += 0.5;
    risk += hasFreeSSLIndicators ? 0.5 : 0.0;

    maxRisk += 0.5;
    risk += hasMixedContentIndicators ? 0.5 : 0.0;

    maxRisk += 0.5;
    risk += hasRedirectPatterns ? 0.5 : 0.0;

    maxRisk += 1.0;
    risk += (1.0 - securityScore);

    return (risk / maxRisk).clamp(0.0, 1.0);
  }

  List<String> get riskIndicators {
    final indicators = <String>[];
    if (!isHttps) indicators.add('Uses insecure HTTP protocol');
    if (hasFreeSSLIndicators) {
      indicators.add('SSL certificate may be from a free/automatic provider');
    }
    if (hasMixedContentIndicators) {
      indicators.add('Potential mixed HTTP/HTTPS content detected');
    }
    if (hasRedirectPatterns) {
      indicators.add('URL contains redirect patterns');
    }
    if (securityScore < 0.5) {
      indicators.add(
        'Low overall security score (${(securityScore * 100).toStringAsFixed(0)}%)',
      );
    }
    return indicators;
  }

  int get featureCount => 5;

  Map<String, dynamic> toMap() => {
    'isHttps': isHttps,
    'hasFreeSSLIndicators': hasFreeSSLIndicators,
    'securityScore': securityScore,
    'hasMixedContentIndicators': hasMixedContentIndicators,
    'hasRedirectPatterns': hasRedirectPatterns,
  };
}

/// Webpage content features (inferred from URL patterns)
class ContentFeatures {
  /// Whether URL suggests a login/credential page
  final bool suggestsLoginPage;

  /// Whether URL contains form submission indicators
  final bool hasFormIndicators;

  /// Whether URL suggests file download
  final bool suggestsDownload;

  /// Whether URL contains data exfiltration patterns
  final bool hasDataExfiltrationPatterns;

  /// Whether URL mimics a legitimate service page
  final bool mimicsLegitimateService;

  /// Content risk score based on URL path patterns
  final double urlPathContentRisk;

  /// Keywords suggesting credential harvesting
  final List<String> credentialKeywords;

  const ContentFeatures({
    required this.suggestsLoginPage,
    required this.hasFormIndicators,
    required this.suggestsDownload,
    required this.hasDataExfiltrationPatterns,
    required this.mimicsLegitimateService,
    required this.urlPathContentRisk,
    required this.credentialKeywords,
  });

  double get riskScore {
    double score = 0;
    double maxScore = 0;

    maxScore += 1.0;
    score += suggestsLoginPage ? 1.0 : 0.0;

    maxScore += 0.7;
    score += hasFormIndicators ? 0.7 : 0.0;

    maxScore += 0.6;
    score += suggestsDownload ? 0.6 : 0.0;

    maxScore += 1.0;
    score += hasDataExfiltrationPatterns ? 1.0 : 0.0;

    maxScore += 0.8;
    score += mimicsLegitimateService ? 0.8 : 0.0;

    maxScore += 1.0;
    score += urlPathContentRisk;

    maxScore += 0.8;
    score += credentialKeywords.isNotEmpty
        ? min(credentialKeywords.length * 0.2, 0.8)
        : 0.0;

    return (score / maxScore).clamp(0.0, 1.0);
  }

  List<String> get riskIndicators {
    final indicators = <String>[];
    if (suggestsLoginPage) {
      indicators.add('URL structure suggests a login/credential page');
    }
    if (hasFormIndicators) {
      indicators.add('URL contains form submission indicators');
    }
    if (suggestsDownload) {
      indicators.add('URL may trigger a file download');
    }
    if (hasDataExfiltrationPatterns) {
      indicators.add('Potential data exfiltration patterns detected');
    }
    if (mimicsLegitimateService) {
      indicators.add('URL structure mimics a legitimate service');
    }
    if (credentialKeywords.isNotEmpty) {
      indicators.add(
        'Credential-related keywords: ${credentialKeywords.take(3).join(", ")}',
      );
    }
    return indicators;
  }

  int get featureCount => 7;

  Map<String, dynamic> toMap() => {
    'suggestsLoginPage': suggestsLoginPage,
    'hasFormIndicators': hasFormIndicators,
    'suggestsDownload': suggestsDownload,
    'hasDataExfiltrationPatterns': hasDataExfiltrationPatterns,
    'mimicsLegitimateService': mimicsLegitimateService,
    'urlPathContentRisk': urlPathContentRisk,
    'credentialKeywords': credentialKeywords,
  };
}

/// Combined multi-modal feature set
class MultiModalFeatureSet {
  final UrlFeatures urlFeatures;
  final SequentialFeatures sequentialFeatures;
  final HostFeatures hostFeatures;
  final SslFeatures sslFeatures;
  final ContentFeatures contentFeatures;

  const MultiModalFeatureSet({
    required this.urlFeatures,
    required this.sequentialFeatures,
    required this.hostFeatures,
    required this.sslFeatures,
    required this.contentFeatures,
  });

  /// Total number of features extracted across all modalities
  int get totalFeatureCount =>
      urlFeatures.featureCount +
      sequentialFeatures.featureCount +
      hostFeatures.featureCount +
      sslFeatures.featureCount +
      contentFeatures.featureCount;

  Map<String, dynamic> toMap() => {
    'urlFeatures': urlFeatures.toMap(),
    'sequentialFeatures': sequentialFeatures.toMap(),
    'hostFeatures': hostFeatures.toMap(),
    'sslFeatures': sslFeatures.toMap(),
    'contentFeatures': contentFeatures.toMap(),
    'totalFeatureCount': totalFeatureCount,
  };
}
