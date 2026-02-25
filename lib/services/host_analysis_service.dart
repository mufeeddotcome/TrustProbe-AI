import 'dart:math';

import '../models/feature_set.dart';

/// HostAnalysisService — Host and domain attribute analysis
///
/// Analyzes host and domain attributes of URLs including TLD reputation,
/// domain structure, brand impersonation patterns, and domain age heuristics.
class HostAnalysisService {
  /// Trusted domains that are known safe
  static const _trustedDomains = [
    'google.com',
    'facebook.com',
    'microsoft.com',
    'amazon.com',
    'apple.com',
    'twitter.com',
    'linkedin.com',
    'github.com',
    'stackoverflow.com',
    'reddit.com',
    'wikipedia.org',
    'youtube.com',
    'instagram.com',
    'whatsapp.com',
    'netflix.com',
    'spotify.com',
    'dropbox.com',
    'slack.com',
    'zoom.us',
    'adobe.com',
    'paypal.com',
    'ebay.com',
    'yahoo.com',
    'bing.com',
    'cloudflare.com',
    'aws.amazon.com',
    'azure.microsoft.com',
    'bankofamerica.com',
    'wellsfargo.com',
    'chase.com',
    'citibank.com',
    'hsbc.com',
    'barclays.com',
    'coinbase.com',
  ];

  /// TLD risk scores — higher = more risky
  static const _tldRiskScores = <String, double>{
    // High risk — commonly abused TLDs
    '.tk': 0.95, '.ml': 0.90, '.ga': 0.90, '.cf': 0.90,
    '.gq': 0.90, '.xyz': 0.75, '.top': 0.80, '.click': 0.85,
    '.link': 0.70, '.work': 0.65, '.buzz': 0.80, '.club': 0.60,
    '.info': 0.50, '.online': 0.65, '.site': 0.65, '.website': 0.70,
    '.space': 0.60, '.icu': 0.80, '.live': 0.55, '.stream': 0.70,
    '.download': 0.75, '.win': 0.80, '.bid': 0.75, '.loan': 0.75,
    '.racing': 0.80, '.review': 0.70, '.date': 0.70, '.faith': 0.70,
    '.party': 0.70, '.science': 0.65, '.trade': 0.70, '.accountant': 0.75,
    '.cricket': 0.70, '.pw': 0.80, '.cn': 0.45, '.ru': 0.50,
    // Medium risk
    '.biz': 0.40, '.cc': 0.45, '.co': 0.30, '.me': 0.25,
    '.io': 0.15, '.tech': 0.35, '.dev': 0.10, '.app': 0.10,
    // Low risk — reputable TLDs
    '.com': 0.05, '.org': 0.08, '.net': 0.10, '.edu': 0.02,
    '.gov': 0.01, '.mil': 0.01, '.int': 0.02, '.us': 0.15,
    '.uk': 0.08, '.de': 0.08, '.fr': 0.08, '.au': 0.08,
    '.ca': 0.08, '.jp': 0.08, '.in': 0.12, '.br': 0.12,
  };

  /// Brand names for impersonation detection
  static const _brandNames = [
    'paypal',
    'facebook',
    'google',
    'amazon',
    'apple',
    'microsoft',
    'netflix',
    'instagram',
    'whatsapp',
    'twitter',
    'linkedin',
    'ebay',
    'bank',
    'chase',
    'wellsfargo',
    'citibank',
    'hsbc',
    'barclays',
    'dropbox',
    'icloud',
    'outlook',
    'yahoo',
    'steam',
    'spotify',
    'coinbase',
    'binance',
    'blockchain',
    'metamask',
    'wallet',
  ];

  /// URL shortener domains
  static const _urlShorteners = [
    'bit.ly',
    'tinyurl.com',
    'goo.gl',
    'ow.ly',
    't.co',
    'is.gd',
    'buff.ly',
    'adf.ly',
    'tiny.cc',
    'shorte.st',
    'cutt.ly',
    'rb.gy',
    'shorturl.at',
    'v.gd',
  ];

  /// Analyze host and domain features
  HostFeatures analyze(Uri parsedUrl) {
    final domain = parsedUrl.host.toLowerCase();

    final isTrusted = _isTrustedDomain(domain);
    final (impersonationScore, impersonatedBrand) = _detectBrandImpersonation(
      domain,
    );

    return HostFeatures(
      tldRiskScore: _getTldRiskScore(domain),
      domainStructureRisk: _analyzeDomainStructure(domain),
      brandImpersonationScore: impersonationScore,
      isIpAddress: _isIpAddress(domain),
      isUrlShortener: _isUrlShortener(domain),
      subdomainDepth: _getSubdomainDepth(domain),
      domainRandomnessScore: _domainRandomness(domain),
      impersonatedBrand: impersonatedBrand,
      isTrustedDomain: isTrusted,
      domainAgeRisk: _estimateDomainAgeRisk(domain),
    );
  }

  bool _isTrustedDomain(String domain) => _trustedDomains.any(
    (trusted) => domain == trusted || domain.endsWith('.$trusted'),
  );

  double _getTldRiskScore(String domain) {
    for (final entry in _tldRiskScores.entries) {
      if (domain.endsWith(entry.key)) return entry.value;
    }
    return 0.20; // Unknown TLD — moderate default risk
  }

  double _analyzeDomainStructure(String domain) {
    double risk = 0;

    // Excessive length
    if (domain.length > 30) risk += 0.3;
    if (domain.length > 50) risk += 0.3;

    // Excessive dashes
    final dashCount = domain.split('-').length - 1;
    if (dashCount > 3) risk += 0.3;
    if (dashCount > 5) risk += 0.2;

    // Excessive dots (subdomains)
    final dotCount = domain.split('.').length - 1;
    if (dotCount > 3) risk += 0.2;

    // Numbers in domain
    final digitCount = domain.replaceAll(RegExp(r'[^0-9]'), '').length;
    if (digitCount > 4) risk += 0.2;

    return risk.clamp(0.0, 1.0);
  }

  (double, String?) _detectBrandImpersonation(String domain) {
    for (final brand in _brandNames) {
      if (domain.contains(brand)) {
        // Check if it's the legitimate domain
        if (domain == '$brand.com' ||
            domain.endsWith('.$brand.com') ||
            domain == '$brand.org' ||
            domain.endsWith('.$brand.org')) {
          return (0.0, null); // Legitimate
        }
        // Calculate impersonation confidence
        double confidence = 0.7;
        // Higher confidence if combined with suspicious TLDs
        if (_getTldRiskScore(domain) > 0.5) confidence += 0.2;
        // Higher if brand is part of subdomain
        if (domain.startsWith('$brand.') || domain.startsWith('$brand-')) {
          confidence += 0.1;
        }
        return (confidence.clamp(0.0, 1.0), brand);
      }
    }
    return (0.0, null);
  }

  bool _isIpAddress(String domain) =>
      RegExp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$').hasMatch(domain);

  bool _isUrlShortener(String domain) =>
      _urlShorteners.any((s) => domain == s || domain.endsWith('.$s'));

  int _getSubdomainDepth(String domain) {
    final parts = domain.split('.');
    return parts.length > 2 ? parts.length - 2 : 0;
  }

  double _domainRandomness(String domain) {
    // Remove TLD to analyze the domain name itself
    final parts = domain.split('.');
    if (parts.length < 2) return 0;
    final domainName = parts.sublist(0, parts.length - 1).join('');

    if (domainName.length < 4) return 0;

    // Count vowels
    const vowels = 'aeiou';
    final alpha = domainName
        .split('')
        .where((c) => RegExp(r'[a-z]').hasMatch(c));
    if (alpha.isEmpty) return 0.5;

    final vowelRatio =
        alpha.where((c) => vowels.contains(c)).length / alpha.length;

    // Very low vowel ratio suggests random generation
    if (vowelRatio < 0.15) return 0.9;
    if (vowelRatio < 0.2) return 0.6;

    // Entropy-based randomness check
    final entropy = _simpleEntropy(domainName);
    if (entropy > 4.0) return 0.7;
    if (entropy > 3.5) return 0.3;

    return 0.0;
  }

  double _simpleEntropy(String s) {
    if (s.isEmpty) return 0;
    final freq = <String, int>{};
    for (final c in s.split('')) {
      freq[c] = (freq[c] ?? 0) + 1;
    }
    double entropy = 0;
    for (final count in freq.values) {
      final p = count / s.length;
      if (p > 0) entropy -= p * (log(p) / ln2);
    }
    return entropy;
  }

  /// Heuristic domain age risk — newer-looking domains score higher
  double _estimateDomainAgeRisk(String domain) {
    double risk = 0;

    // Domains with high-risk TLDs tend to be newer/disposable
    if (_getTldRiskScore(domain) > 0.6) risk += 0.4;

    // Very long domains with dashes suggest recently created phishing domains
    if (domain.length > 25 && domain.contains('-')) risk += 0.3;

    // Domains with numbers mixed in are often generated
    final hasDigits = RegExp(r'[0-9]').hasMatch(domain.split('.').first);
    if (hasDigits) risk += 0.2;

    // Random-looking domains are likely new
    if (_domainRandomness(domain) > 0.5) risk += 0.3;

    return risk.clamp(0.0, 1.0);
  }
}
