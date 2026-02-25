import '../models/feature_set.dart';

/// SslAnalysisService — SSL/TLS and security attribute analysis
///
/// Analyzes SSL/security characteristics of URLs including protocol
/// verification, certificate indicators, and security patterns.
class SslAnalysisService {
  /// Analyze SSL/security features of a URL
  SslFeatures analyze(String url, Uri parsedUrl) {
    final isHttps = parsedUrl.scheme == 'https';
    final fullUrl = url.toLowerCase();

    return SslFeatures(
      isHttps: isHttps,
      hasFreeSSLIndicators: _detectFreeSSLIndicators(parsedUrl.host),
      securityScore: _calculateSecurityScore(isHttps, parsedUrl),
      hasMixedContentIndicators: _detectMixedContent(fullUrl),
      hasRedirectPatterns: _detectRedirectPatterns(fullUrl),
    );
  }

  /// Detect indicators of free/automatic SSL certificates
  /// Free certs are not inherently bad but are heavily used by phishing sites
  bool _detectFreeSSLIndicators(String domain) {
    // Domains on free hosting often have specific patterns
    const freeHostingPatterns = [
      'herokuapp.com',
      'netlify.app',
      'vercel.app',
      'pages.dev',
      'web.app',
      'firebaseapp.com',
      'azurewebsites.net',
      'blogspot.com',
      'wordpress.com',
      'wixsite.com',
      'weebly.com',
      '000webhostapp.com',
      'rf.gd',
      'infinityfreeapp.com',
    ];
    return freeHostingPatterns.any((p) => domain.endsWith(p));
  }

  /// Calculate overall security score based on multiple factors
  double _calculateSecurityScore(bool isHttps, Uri url) {
    double score = 0;
    double maxScore = 0;

    // HTTPS is the most important factor
    maxScore += 1.0;
    score += isHttps ? 1.0 : 0.0;

    // Standard ports are more trustworthy
    maxScore += 0.5;
    if (!url.hasPort || url.port == 80 || url.port == 443) {
      score += 0.5;
    }

    // Short, clean URLs tend to be safer
    maxScore += 0.3;
    if (url.toString().length < 80) score += 0.3;

    // URLs without @ symbol are safer
    maxScore += 0.2;
    if (!url.toString().contains('@')) score += 0.2;

    return (score / maxScore).clamp(0.0, 1.0);
  }

  /// Detect mixed content indicators in URL
  bool _detectMixedContent(String url) {
    // Check for HTTP references within an HTTPS URL
    if (url.startsWith('https://')) {
      // URLs that reference HTTP resources in query params
      return url.contains('http%3a') ||
          url.contains('http%3A') ||
          (url.contains('redirect=http:') ||
              url.contains('url=http:') ||
              url.contains('next=http:') ||
              url.contains('return=http:'));
    }
    return false;
  }

  /// Detect URL redirect patterns (often used in phishing)
  bool _detectRedirectPatterns(String url) {
    const redirectIndicators = [
      'redirect=',
      'redirect_uri=',
      'return_url=',
      'next=',
      'url=',
      'goto=',
      'target=',
      'rurl=',
      'dest=',
      'destination=',
      'returnto=',
      'return_to=',
      'continue=',
      'forward=',
      'link=',
      'site=',
    ];
    return redirectIndicators.any((r) => url.contains(r));
  }
}
