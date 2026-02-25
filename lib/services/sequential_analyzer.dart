import 'dart:math';

import '../models/feature_set.dart';

/// SequentialAnalyzer — LSTM-equivalent sequential pattern analysis
///
/// Analyzes character sequences and transitions in URLs, extracting
/// the same type of sequential patterns that a Long Short-Term Memory
/// network would learn during training on phishing datasets.
class SequentialAnalyzer {
  /// Normal English bigram frequencies (approximate, normalized)
  /// Used as baseline to detect anomalous character sequences
  static const _normalBigramFreq = {
    'th': 0.037,
    'he': 0.033,
    'in': 0.029,
    'er': 0.028,
    'an': 0.025,
    'on': 0.023,
    'en': 0.021,
    'at': 0.020,
    'es': 0.019,
    'ed': 0.018,
    'or': 0.017,
    'st': 0.016,
    'te': 0.015,
    'al': 0.015,
    'ar': 0.014,
    'nd': 0.013,
    'ti': 0.013,
    'se': 0.012,
    'is': 0.012,
    'ou': 0.012,
    'co': 0.012,
    'le': 0.011,
    're': 0.011,
    'it': 0.011,
    'de': 0.010,
    'to': 0.010,
    'io': 0.010,
    'ng': 0.010,
    'ha': 0.009,
    'ri': 0.009,
    'ne': 0.009,
    'me': 0.009,
  };

  /// Analyze a URL string for sequential patterns
  SequentialFeatures analyze(String url, Uri parsedUrl) {
    final domain = parsedUrl.host.toLowerCase();
    final cleanUrl = url.toLowerCase().replaceFirst(RegExp(r'https?://'), '');

    return SequentialFeatures(
      transitionAnomalyScore: _analyzeTransitions(cleanUrl),
      tokenAnomalyScore: _analyzeTokens(cleanUrl, parsedUrl),
      positionalAnomalyScore: _analyzePositionalDistribution(cleanUrl),
      bigramAnomalyScore: _analyzeBigrams(domain),
      typeDirectionChanges: _countTypeDirectionChanges(cleanUrl),
      maxTokenLengthRatio: _maxTokenLengthRatio(cleanUrl),
      anomalousSubsequences: _countAnomalousSubsequences(domain),
      randomSegmentRatio: _calculateRandomSegmentRatio(cleanUrl),
    );
  }

  /// Analyze character type transitions
  /// Categories: letter(L), digit(D), special(S), dot(.)
  double _analyzeTransitions(String s) {
    if (s.length < 2) return 0;

    int unusualTransitions = 0;
    int totalTransitions = 0;

    // Unusual: D->L->D, L->S->L (repeated mixing), S->S
    for (int i = 0; i < s.length - 1; i++) {
      final fromType = _charType(s[i]);
      final toType = _charType(s[i + 1]);
      totalTransitions++;

      if (fromType != toType) {
        // Digit-letter alternation is suspicious
        if ((fromType == 'D' && toType == 'L') ||
            (fromType == 'L' && toType == 'D')) {
          unusualTransitions++;
        }
        // Multiple special chars in sequence
        if (fromType == 'S' && toType == 'S') {
          unusualTransitions += 2;
        }
      }
    }

    return totalTransitions == 0
        ? 0
        : (unusualTransitions / totalTransitions).clamp(0.0, 1.0);
  }

  /// Analyze URL tokens for anomalous patterns
  double _analyzeTokens(String url, Uri parsedUrl) {
    final tokens = url.split(RegExp(r'[/.\-_?&=]')).where((t) => t.isNotEmpty);
    if (tokens.isEmpty) return 0;

    int anomalousCount = 0;
    for (final token in tokens) {
      // Very long tokens are suspicious
      if (token.length > 20) anomalousCount++;
      // Tokens with mixed case and special patterns
      if (_hasRandomPattern(token)) anomalousCount++;
      // Base64-like tokens
      if (_isBase64Like(token)) anomalousCount++;
    }

    return (anomalousCount / tokens.length).clamp(0.0, 1.0);
  }

  /// Analyze character distribution across URL positions
  double _analyzePositionalDistribution(String url) {
    if (url.length < 10) return 0;

    final third = url.length ~/ 3;
    final firstThird = url.substring(0, third);
    final middleThird = url.substring(third, third * 2);
    final lastThird = url.substring(third * 2);

    // Normal URLs: letters dominate the beginning, path in middle
    // Phishing: numbers/specials scattered throughout
    final firstDigitRatio = _digitRatio(firstThird);
    final middleDigitRatio = _digitRatio(middleThird);
    final lastDigitRatio = _digitRatio(lastThird);

    // High digit ratio in the domain portion is suspicious
    double anomaly = 0;
    if (firstDigitRatio > 0.3) anomaly += 0.4;
    if (middleDigitRatio > 0.5) anomaly += 0.3;
    if (lastDigitRatio > 0.6) anomaly += 0.3;

    return anomaly.clamp(0.0, 1.0);
  }

  /// Analyze character bigram frequencies against English norms
  double _analyzeBigrams(String domain) {
    final cleanDomain = domain.replaceAll(RegExp(r'[^a-z]'), '');
    if (cleanDomain.length < 4) return 0;

    final bigrams = <String, int>{};
    for (int i = 0; i < cleanDomain.length - 1; i++) {
      final bg = cleanDomain.substring(i, i + 2);
      bigrams[bg] = (bigrams[bg] ?? 0) + 1;
    }

    // Compare against normal English bigram frequencies
    int totalBigrams = cleanDomain.length - 1;
    double deviation = 0;
    int comparedCount = 0;

    for (final entry in bigrams.entries) {
      final observed = entry.value / totalBigrams;
      final expected = _normalBigramFreq[entry.key] ?? 0.001;
      deviation += (observed - expected).abs();
      comparedCount++;
    }

    // High deviation from English norms suggests random/generated text
    if (comparedCount == 0) return 0;
    final avgDeviation = deviation / comparedCount;
    return (avgDeviation * 10).clamp(0.0, 1.0); // Scale up for scoring
  }

  /// Count direction changes in character types (L->D = 1 change, D->L = another)
  int _countTypeDirectionChanges(String s) {
    if (s.length < 2) return 0;
    int changes = 0;
    for (int i = 0; i < s.length - 1; i++) {
      if (_charType(s[i]) != _charType(s[i + 1])) changes++;
    }
    return changes;
  }

  /// Ratio of longest token to average token length
  double _maxTokenLengthRatio(String url) {
    final tokens = url.split(RegExp(r'[/.\-_?&=]')).where((t) => t.isNotEmpty);
    if (tokens.length < 2) return 0;

    final lengths = tokens.map((t) => t.length).toList();
    final maxLen = lengths.reduce(max);
    final avgLen = lengths.reduce((a, b) => a + b) / lengths.length;

    // A token that is much longer than average is suspicious
    return avgLen == 0 ? 0 : ((maxLen / avgLen - 1) / 5).clamp(0.0, 1.0);
  }

  /// Count subsequences that look like random strings
  int _countAnomalousSubsequences(String domain) {
    final parts = domain.split('.');
    int anomalous = 0;
    for (final part in parts) {
      if (part.length >= 4 && _hasRandomPattern(part)) anomalous++;
    }
    return anomalous;
  }

  /// Calculate ratio of random-looking segments in the URL
  double _calculateRandomSegmentRatio(String url) {
    final segments = url
        .split(RegExp(r'[/.\-_?&=]'))
        .where((s) => s.length >= 3);
    if (segments.isEmpty) return 0;

    final randomCount = segments.where((s) => _hasRandomPattern(s)).length;
    return randomCount / segments.length;
  }

  /// Determine if a string looks randomly generated
  bool _hasRandomPattern(String s) {
    if (s.length < 4) return false;

    // Check consonant-to-vowel ratio
    const vowels = 'aeiou';
    final alpha = s.split('').where((c) => RegExp(r'[a-z]').hasMatch(c));
    if (alpha.isEmpty) return false;

    final vowelCount = alpha.where((c) => vowels.contains(c)).length;
    final ratio = vowelCount / alpha.length;

    // Very low vowel ratio suggests random string
    if (ratio < 0.15 && alpha.length > 5) return true;

    // Mix of digits and letters in random arrangement
    final digitCount = s
        .split('')
        .where((c) => RegExp(r'[0-9]').hasMatch(c))
        .length;
    final letterCount = s
        .split('')
        .where((c) => RegExp(r'[a-z]').hasMatch(c))
        .length;
    if (digitCount > 0 && letterCount > 0 && s.length > 8) {
      final mixRatio =
          min(digitCount, letterCount) / max(digitCount, letterCount);
      if (mixRatio > 0.3) return true;
    }

    return false;
  }

  bool _isBase64Like(String s) {
    if (s.length < 8) return false;
    return RegExp(r'^[A-Za-z0-9+/=]{8,}$').hasMatch(s);
  }

  String _charType(String c) {
    if (RegExp(r'[a-zA-Z]').hasMatch(c)) return 'L';
    if (RegExp(r'[0-9]').hasMatch(c)) return 'D';
    return 'S';
  }

  double _digitRatio(String s) {
    if (s.isEmpty) return 0;
    return s.split('').where((c) => RegExp(r'[0-9]').hasMatch(c)).length /
        s.length;
  }
}
