import '../models/feature_set.dart';

/// ContentAnalysisService — Webpage content feature analysis
///
/// Analyzes URL patterns to infer likely webpage content characteristics.
/// Detects login pages, form submissions, credential harvesting,
/// and data exfiltration patterns from URL structure alone.
///
/// Note: In a Flutter web app, direct webpage fetching is limited by CORS.
/// This service analyzes URL structure to predict content characteristics
/// that would indicate phishing activity.
class ContentAnalysisService {
  /// Keywords that indicate login/credential pages
  static const _loginKeywords = [
    'login',
    'signin',
    'sign-in',
    'sign_in',
    'logon',
    'log-on',
    'authenticate',
    'auth',
    'sso',
    'cas',
    'oauth',
    'password',
    'passwd',
    'credential',
    'unlock',
  ];

  /// Keywords that indicate form/data submission
  static const _formKeywords = [
    'submit',
    'form',
    'register',
    'signup',
    'sign-up',
    'sign_up',
    'create-account',
    'create_account',
    'enroll',
    'enrollment',
    'apply',
    'application',
    'checkout',
    'payment',
  ];

  /// Keywords that suggest file downloads
  static const _downloadKeywords = [
    'download',
    'install',
    'setup',
    'update',
    'patch',
    'upgrade',
    'driver',
    'software',
    'plugin',
    'extension',
    '.exe',
    '.msi',
    '.dmg',
    '.apk',
    '.zip',
    '.rar',
    '.scr',
    '.bat',
    '.cmd',
    '.vbs',
    '.js',
    '.jar',
  ];

  /// Keywords that suggest data exfiltration
  static const _exfiltrationKeywords = [
    'ssn',
    'social-security',
    'tax',
    'refund',
    'irs',
    'credit-card',
    'card-number',
    'cvv',
    'expiry',
    'bank-account',
    'routing-number',
    'swift',
    'bitcoin',
    'btc',
    'eth',
    'crypto',
    'seed-phrase',
    'private-key',
    'wallet-recovery',
  ];

  /// Keywords indicating impersonation of legitimate services
  static const _serviceKeywords = [
    'verify',
    'verification',
    'confirm',
    'confirmation',
    'secure',
    'security',
    'alert',
    'warning',
    'urgent',
    'suspended',
    'locked',
    'limited',
    'restricted',
    'unusual-activity',
    'unauthorized',
    'suspicious-activity',
    'update-billing',
    'update-payment',
    'expire',
    'expiring',
    'reactivate',
    'restore',
    'recover',
    'recovery',
  ];

  /// Analyze content features based on URL structure
  ContentFeatures analyze(String url, Uri parsedUrl) {
    final lowerUrl = url.toLowerCase();
    final path = parsedUrl.path.toLowerCase();
    final query = parsedUrl.query.toLowerCase();
    final fullSearchable = '$path $query';

    final credentialKeywords = _findMatchingKeywords(fullSearchable, [
      ..._loginKeywords,
      ..._exfiltrationKeywords,
    ]);

    return ContentFeatures(
      suggestsLoginPage: _detectLoginPage(fullSearchable),
      hasFormIndicators: _detectFormIndicators(fullSearchable),
      suggestsDownload: _detectDownload(lowerUrl),
      hasDataExfiltrationPatterns: _detectDataExfiltration(fullSearchable),
      mimicsLegitimateService: _detectServiceMimicry(lowerUrl),
      urlPathContentRisk: _calculatePathContentRisk(path, query),
      credentialKeywords: credentialKeywords,
    );
  }

  bool _detectLoginPage(String searchable) =>
      _loginKeywords.any((k) => searchable.contains(k));

  bool _detectFormIndicators(String searchable) =>
      _formKeywords.any((k) => searchable.contains(k));

  bool _detectDownload(String url) =>
      _downloadKeywords.any((k) => url.contains(k));

  bool _detectDataExfiltration(String searchable) =>
      _exfiltrationKeywords.any((k) => searchable.contains(k));

  bool _detectServiceMimicry(String url) =>
      _serviceKeywords.any((k) => url.contains(k));

  List<String> _findMatchingKeywords(
    String searchable,
    List<String> keywords,
  ) => keywords.where((k) => searchable.contains(k)).toList();

  /// Calculate content risk from URL path patterns
  double _calculatePathContentRisk(String path, String query) {
    double risk = 0;

    // Login-related paths
    if (_loginKeywords.any((k) => path.contains(k))) risk += 0.3;

    // Encoded content in query (potential data theft)
    if (query.contains('%3d') || query.contains('%3D')) risk += 0.1;

    // Very long query strings suggest data-heavy requests
    if (query.length > 100) risk += 0.2;

    // Multiple encoded parameters
    if (query.split('&').length > 5) risk += 0.1;

    // Data exfiltration keywords
    if (_exfiltrationKeywords.any(
      (k) => path.contains(k) || query.contains(k),
    )) {
      risk += 0.3;
    }

    // Service mimicry keywords
    if (_serviceKeywords.any((k) => path.contains(k))) risk += 0.2;

    return risk.clamp(0.0, 1.0);
  }
}
