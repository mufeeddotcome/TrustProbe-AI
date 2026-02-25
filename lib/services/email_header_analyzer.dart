import '../models/email_feature_set.dart';
import '../services/email_parser.dart';

/// EmailHeaderAnalyzer — Analyzes email sender and header attributes
///
/// Detects sender domain reputation, spoofing, reply-to mismatch,
/// display name impersonation, and free email provider usage.
class EmailHeaderAnalyzer {
  /// Free email providers — not inherently malicious, but suspicious
  /// when impersonating organizations
  static const _freeEmailProviders = [
    'gmail.com',
    'yahoo.com',
    'hotmail.com',
    'outlook.com',
    'aol.com',
    'icloud.com',
    'mail.com',
    'protonmail.com',
    'zoho.com',
    'yandex.com',
    'gmx.com',
    'live.com',
    'msn.com',
    'rocketmail.com',
    'inbox.com',
  ];

  /// Known brand domains for spoofing detection
  static const _brandDomains = <String, List<String>>{
    'paypal': ['paypal.com'],
    'google': ['google.com', 'gmail.com', 'googlemail.com'],
    'microsoft': ['microsoft.com', 'outlook.com', 'hotmail.com', 'live.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de'],
    'apple': ['apple.com', 'icloud.com'],
    'facebook': ['facebook.com', 'meta.com', 'fb.com'],
    'netflix': ['netflix.com'],
    'bank': [
      'bankofamerica.com',
      'chase.com',
      'wellsfargo.com',
      'citibank.com',
      'hsbc.com',
    ],
    'instagram': ['instagram.com'],
    'twitter': ['twitter.com', 'x.com'],
    'linkedin': ['linkedin.com'],
    'dropbox': ['dropbox.com'],
    'spotify': ['spotify.com'],
    'coinbase': ['coinbase.com'],
  };

  /// High-risk TLDs for sender domain
  static const _highRiskTlds = [
    '.tk',
    '.ml',
    '.ga',
    '.cf',
    '.gq',
    '.xyz',
    '.top',
    '.click',
    '.buzz',
    '.icu',
    '.work',
    '.link',
    '.pw',
  ];

  EmailHeaderFeatures analyze(ParsedEmail email) {
    final senderDomain = email.senderDomain ?? '';
    final senderEmail = email.senderEmail ?? '';

    return EmailHeaderFeatures(
      senderDomainRisk: _senderDomainRisk(senderDomain),
      isFreeEmailProvider: _isFreeProvider(senderDomain),
      hasReplyToMismatch: email.hasReplyToMismatch,
      displayNameImpersonation: _displayNameImpersonation(email),
      hasSpoofingIndicators: _detectSpoofing(senderEmail, senderDomain),
      brandSpoofScore: _brandSpoofScore(senderEmail, senderDomain),
      impersonatedBrand: _detectBrandImpersonation(
        senderEmail,
        senderDomain,
        email,
      ),
      headerAnomalyCount: _countHeaderAnomalies(email),
    );
  }

  double _senderDomainRisk(String domain) {
    if (domain.isEmpty) return 0.5;

    // Check high-risk TLDs
    for (final tld in _highRiskTlds) {
      if (domain.endsWith(tld)) return 0.9;
    }

    // Check if domain is a known legitimate brand
    for (final domains in _brandDomains.values) {
      if (domains.contains(domain)) return 0.0;
    }

    // Free providers are moderate risk
    if (_isFreeProvider(domain)) return 0.3;

    // Common TLDs
    if (domain.endsWith('.com') ||
        domain.endsWith('.org') ||
        domain.endsWith('.net') ||
        domain.endsWith('.edu') ||
        domain.endsWith('.gov')) {
      return 0.15;
    }

    return 0.4; // Unknown domain
  }

  bool _isFreeProvider(String domain) =>
      _freeEmailProviders.contains(domain.toLowerCase());

  double _displayNameImpersonation(ParsedEmail email) {
    final displayName = email.senderDisplayName?.toLowerCase() ?? '';
    if (displayName.isEmpty) return 0.0;

    double score = 0;

    // Check if display name contains brand names
    for (final brand in _brandDomains.keys) {
      if (displayName.contains(brand)) {
        // Check if the email domain matches the brand
        final brandDomains = _brandDomains[brand]!;
        final senderDomain = email.senderDomain?.toLowerCase() ?? '';
        if (!brandDomains.contains(senderDomain)) {
          score = 0.9; // Display name says brand but domain doesn't match
        }
        break;
      }
    }

    // Check for authority impersonation
    final authorityTerms = [
      'ceo',
      'cfo',
      'director',
      'manager',
      'admin',
      'support',
      'helpdesk',
      'security',
      'it department',
      'hr department',
    ];
    for (final term in authorityTerms) {
      if (displayName.contains(term)) {
        score = (score + 0.4).clamp(0.0, 1.0);
        break;
      }
    }

    return score;
  }

  bool _detectSpoofing(String senderEmail, String domain) {
    if (domain.isEmpty) return false;

    // Check for common spoofing patterns
    // Domain contains a brand name but isn't the real domain
    for (final entry in _brandDomains.entries) {
      if (domain.contains(entry.key) && !entry.value.contains(domain)) {
        return true;
      }
    }

    // Domain with excessive dashes/dots
    final dashCount = domain.split('-').length - 1;
    final dotCount = domain.split('.').length - 1;
    if (dashCount > 3 || dotCount > 3) return true;

    return false;
  }

  double _brandSpoofScore(String senderEmail, String domain) {
    if (domain.isEmpty) return 0.0;

    for (final entry in _brandDomains.entries) {
      final brand = entry.key;
      final legitimateDomains = entry.value;

      if (domain.contains(brand) && !legitimateDomains.contains(domain)) {
        return 0.85;
      }
      if (senderEmail.toLowerCase().contains(brand) &&
          !legitimateDomains.contains(domain)) {
        return 0.7;
      }
    }

    return 0.0;
  }

  String? _detectBrandImpersonation(
    String senderEmail,
    String domain,
    ParsedEmail email,
  ) {
    // Check sender domain
    for (final entry in _brandDomains.entries) {
      if (domain.contains(entry.key) && !entry.value.contains(domain)) {
        return entry.key;
      }
    }

    // Check display name
    final displayName = email.senderDisplayName?.toLowerCase() ?? '';
    for (final brand in _brandDomains.keys) {
      if (displayName.contains(brand)) {
        final brandDomains = _brandDomains[brand]!;
        if (!brandDomains.contains(domain)) {
          return brand;
        }
      }
    }

    // Check subject line
    final subject = email.subject?.toLowerCase() ?? '';
    for (final brand in _brandDomains.keys) {
      if (subject.contains(brand)) {
        final brandDomains = _brandDomains[brand]!;
        if (!brandDomains.contains(domain)) {
          return brand;
        }
      }
    }

    return null;
  }

  int _countHeaderAnomalies(ParsedEmail email) {
    int count = 0;
    if (email.hasReplyToMismatch) count++;
    if (email.senderEmail == null && email.body.isNotEmpty) count++;
    if (email.senderDisplayName != null &&
        email.senderEmail != null &&
        !email.senderDisplayName!.contains('@') &&
        email.senderDisplayName!.contains(RegExp(r'[<>]'))) {
      count++; // Malformed display name
    }
    return count;
  }
}
