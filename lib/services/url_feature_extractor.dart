import 'dart:math';

import '../models/feature_set.dart';

/// UrlFeatureExtractor — CNN-equivalent character-level feature extraction
///
/// Extracts 25+ numeric features from URL strings, mirroring the
/// character-level patterns that a Convolutional Neural Network
/// would learn during training on phishing datasets.
class UrlFeatureExtractor {
  /// Extract all URL lexical features from a URL string
  UrlFeatures extract(String url, Uri parsedUrl) {
    final lowerUrl = url.toLowerCase();
    final domain = parsedUrl.host.toLowerCase();
    final path = parsedUrl.path;

    return UrlFeatures(
      entropy: _calculateEntropy(lowerUrl),
      urlLength: url.length,
      domainLength: domain.length,
      pathLength: path.length,
      dotCount: _countChar(lowerUrl, '.'),
      dashCount: _countChar(lowerUrl, '-'),
      underscoreCount: _countChar(lowerUrl, '_'),
      digitCount: _countDigits(lowerUrl),
      digitRatio: _digitRatio(lowerUrl),
      specialCharCount: _countSpecialChars(lowerUrl),
      specialCharRatio: _specialCharRatio(lowerUrl),
      uppercaseCount: _countUppercase(url),
      uppercaseRatio: _uppercaseRatio(url),
      pathDepth: _pathDepth(path),
      queryParamCount: parsedUrl.queryParameters.length,
      hasFragment: parsedUrl.fragment.isNotEmpty,
      hasPort: parsedUrl.hasPort,
      hasNonStandardPort: _isNonStandardPort(parsedUrl),
      longestConsonantRun: _longestConsonantRun(domain),
      repeatedCharSequences: _countRepeatedSequences(lowerUrl),
      vowelConsonantRatio: _vowelConsonantRatio(domain),
      charVariety: _charVariety(lowerUrl),
      avgWordLengthInDomain: _avgWordLength(domain),
      subdomainCount: _subdomainCount(domain),
      domainIsHexLike: _isHexLike(domain),
      atSymbolCount: _countChar(lowerUrl, '@'),
    );
  }

  /// Calculate Shannon entropy of a string
  double _calculateEntropy(String s) {
    if (s.isEmpty) return 0.0;
    final freq = <String, int>{};
    for (final c in s.split('')) {
      freq[c] = (freq[c] ?? 0) + 1;
    }
    double entropy = 0.0;
    for (final count in freq.values) {
      final p = count / s.length;
      if (p > 0) entropy -= p * (log(p) / ln2);
    }
    return entropy;
  }

  int _countChar(String s, String c) => s.split(c).length - 1;

  int _countDigits(String s) => s.split('').where((c) => _isDigit(c)).length;

  double _digitRatio(String s) => s.isEmpty ? 0 : _countDigits(s) / s.length;

  int _countSpecialChars(String s) {
    const special = '!@#\$%^&*()=+[]{}|;:\'",<>?/\\~`';
    return s.split('').where((c) => special.contains(c)).length;
  }

  double _specialCharRatio(String s) =>
      s.isEmpty ? 0 : _countSpecialChars(s) / s.length;

  int _countUppercase(String s) => s
      .split('')
      .where(
        (c) =>
            c != c.toLowerCase() &&
            c == c.toUpperCase() &&
            RegExp(r'[A-Z]').hasMatch(c),
      )
      .length;

  double _uppercaseRatio(String s) {
    final alphaCount = s
        .split('')
        .where((c) => RegExp(r'[a-zA-Z]').hasMatch(c))
        .length;
    return alphaCount == 0 ? 0 : _countUppercase(s) / alphaCount;
  }

  int _pathDepth(String path) {
    if (path.isEmpty || path == '/') return 0;
    return path.split('/').where((s) => s.isNotEmpty).length;
  }

  bool _isNonStandardPort(Uri url) {
    if (!url.hasPort) return false;
    return url.port != 80 && url.port != 443;
  }

  int _longestConsonantRun(String s) {
    const vowels = 'aeiou';
    int maxRun = 0;
    int currentRun = 0;
    for (final c in s.split('')) {
      if (RegExp(r'[a-z]').hasMatch(c) && !vowels.contains(c)) {
        currentRun++;
        maxRun = max(maxRun, currentRun);
      } else {
        currentRun = 0;
      }
    }
    return maxRun;
  }

  int _countRepeatedSequences(String s) {
    int count = 0;
    for (int i = 0; i < s.length - 2; i++) {
      if (s[i] == s[i + 1] && s[i + 1] == s[i + 2]) count++;
    }
    return count;
  }

  double _vowelConsonantRatio(String s) {
    const vowels = 'aeiou';
    int vowelCount = 0;
    int consonantCount = 0;
    for (final c in s.split('')) {
      if (!RegExp(r'[a-z]').hasMatch(c)) continue;
      if (vowels.contains(c)) {
        vowelCount++;
      } else {
        consonantCount++;
      }
    }
    return consonantCount == 0 ? 0 : vowelCount / consonantCount;
  }

  double _charVariety(String s) {
    if (s.isEmpty) return 0;
    return s.split('').toSet().length / s.length;
  }

  double _avgWordLength(String domain) {
    // Split domain by dots and dashes to get "words"
    final words = domain.split(RegExp(r'[.\-]')).where((w) => w.isNotEmpty);
    if (words.isEmpty) return 0;
    return words.map((w) => w.length).reduce((a, b) => a + b) / words.length;
  }

  int _subdomainCount(String domain) {
    final parts = domain.split('.');
    return parts.length > 2 ? parts.length - 2 : 0;
  }

  bool _isHexLike(String domain) {
    final domainWithoutDots = domain.replaceAll('.', '');
    if (domainWithoutDots.length < 6) return false;
    final hexChars = domainWithoutDots
        .split('')
        .where((c) => RegExp(r'[0-9a-f]').hasMatch(c))
        .length;
    return hexChars / domainWithoutDots.length > 0.8;
  }

  bool _isDigit(String c) =>
      c.length == 1 && c.codeUnitAt(0) >= 48 && c.codeUnitAt(0) <= 57;
}
