import 'dart:math';

import '../models/email_feature_set.dart';
import '../services/email_parser.dart';

/// EmailContentAnalyzer — Analyzes email body text for phishing patterns
///
/// Detects urgency language, credential requests, social engineering tactics,
/// financial lures, threat language, and grammar anomalies.
class EmailContentAnalyzer {
  /// Urgency keywords and phrases
  static const _urgencyPatterns = [
    'urgent',
    'immediately',
    'asap',
    'right away',
    'right now',
    'act now',
    'don\'t delay',
    'time sensitive',
    'limited time',
    'expires today',
    'expires soon',
    'last chance',
    'final notice',
    'within 24 hours',
    'within 48 hours',
    'action required',
    'immediate action',
    'respond immediately',
    'do not ignore',
    'your account will be',
    'will be suspended',
    'will be closed',
    'will be terminated',
    'will be locked',
    'will be deleted',
    'failure to',
    'if you do not',
    'unless you',
  ];

  /// Credential/personal info request patterns
  static const _credentialPatterns = [
    'password',
    'login',
    'sign in',
    'signin',
    'log in',
    'verify your account',
    'verify your identity',
    'confirm your',
    'update your information',
    'update your account',
    'update your details',
    'social security',
    'ssn',
    'credit card',
    'card number',
    'bank account',
    'routing number',
    'pin number',
    'cvv',
    'enter your',
    'provide your',
    'submit your',
    'send your',
    'click here to verify',
    'click here to confirm',
    'click the link below',
    'click the button below',
    'reset your password',
    'change your password',
  ];

  /// Social engineering patterns
  static const _socialEngineeringPatterns = [
    'dear customer',
    'dear user',
    'dear member',
    'dear valued',
    'dear account holder',
    'dear sir/madam',
    'dear friend',
    'we have detected',
    'we have noticed',
    'we have identified',
    'unusual activity',
    'suspicious activity',
    'unauthorized access',
    'security alert',
    'security notice',
    'security update',
    'your account has been',
    'your account is',
    'for your safety',
    'for your protection',
    'for your security',
    'to protect your account',
    'to secure your account',
    'we need you to',
    'you are required to',
    'you must',
  ];

  /// Financial lure patterns
  static const _financialLurePatterns = [
    'congratulations',
    'you have won',
    'you\'ve won',
    'winner',
    'prize',
    'reward',
    'bonus',
    'free gift',
    'gift card',
    'refund',
    'tax refund',
    'unclaimed',
    'inheritance',
    'million dollars',
    'thousand dollars',
    'transfer funds',
    'wire transfer',
    'bitcoin',
    'cryptocurrency',
    'investment',
    'guaranteed return',
    'risk free',
    'no risk',
    'easy money',
    'make money',
    'earn money',
    'cash prize',
    'lottery',
  ];

  /// Threat / fear language patterns
  static const _threatPatterns = [
    'legal action',
    'law enforcement',
    'police',
    'arrest',
    'court order',
    'subpoena',
    'warrant',
    'fine',
    'penalty',
    'prosecution',
    'criminal charges',
    'account compromised',
    'data breach',
    'hacked',
    'unauthorized transaction',
    'fraudulent activity',
    'identity theft',
    'stolen',
    'compromised',
    'blocked',
    'restricted',
    'suspended',
    'disabled',
  ];

  /// Authority impersonation patterns
  static const _authorityPatterns = [
    'ceo',
    'cfo',
    'cto',
    'president',
    'vice president',
    'director',
    'manager',
    'hr department',
    'it department',
    'helpdesk',
    'tech support',
    'customer support',
    'system administrator',
    'admin',
    'security team',
    'compliance officer',
    'irs',
    'fbi',
    'government',
  ];

  EmailContentFeatures analyze(ParsedEmail email) {
    final body = email.body.toLowerCase();
    final subject = (email.subject ?? '').toLowerCase();
    final fullText = '$subject $body';

    final urgencyResult = _analyzeUrgency(fullText);
    final credentialResult = _analyzeCredentialRequests(fullText);
    final socialResult = _analyzeSocialEngineering(fullText);
    final financialResult = _analyzeFinancialLures(fullText);
    final threatResult = _analyzeThreatLanguage(fullText);
    final grammarResult = _analyzeGrammar(email.body);
    final isAuthority = _detectAuthorityImpersonation(fullText, email);

    // Collect suspicious phrases
    final suspiciousPhrases = <String>[
      ...urgencyResult.$2.take(2),
      ...credentialResult.$2.take(2),
      ...socialResult.$2.take(1),
    ];

    return EmailContentFeatures(
      urgencyScore: urgencyResult.$1,
      urgencyKeywordCount: urgencyResult.$2.length,
      credentialRequestScore: credentialResult.$1,
      socialEngineeringScore: socialResult.$1,
      financialLureScore: financialResult.$1,
      threatLanguageScore: threatResult.$1,
      grammarAnomalyScore: grammarResult,
      impersonatesAuthority: isAuthority,
      suspiciousPhrases: suspiciousPhrases,
    );
  }

  (double, List<String>) _analyzeUrgency(String text) {
    final found = <String>[];
    for (final pattern in _urgencyPatterns) {
      if (text.contains(pattern)) found.add(pattern);
    }
    final score = found.isEmpty
        ? 0.0
        : min(found.length / 3.0, 1.0); // 3+ urgency patterns = max score
    return (score, found);
  }

  (double, List<String>) _analyzeCredentialRequests(String text) {
    final found = <String>[];
    for (final pattern in _credentialPatterns) {
      if (text.contains(pattern)) found.add(pattern);
    }
    final score = found.isEmpty
        ? 0.0
        : min(found.length / 2.0, 1.0); // 2+ credential patterns = max
    return (score, found);
  }

  (double, List<String>) _analyzeSocialEngineering(String text) {
    final found = <String>[];
    for (final pattern in _socialEngineeringPatterns) {
      if (text.contains(pattern)) found.add(pattern);
    }
    final score = found.isEmpty ? 0.0 : min(found.length / 3.0, 1.0);
    return (score, found);
  }

  (double, List<String>) _analyzeFinancialLures(String text) {
    final found = <String>[];
    for (final pattern in _financialLurePatterns) {
      if (text.contains(pattern)) found.add(pattern);
    }
    final score = found.isEmpty ? 0.0 : min(found.length / 2.0, 1.0);
    return (score, found);
  }

  (double, List<String>) _analyzeThreatLanguage(String text) {
    final found = <String>[];
    for (final pattern in _threatPatterns) {
      if (text.contains(pattern)) found.add(pattern);
    }
    final score = found.isEmpty ? 0.0 : min(found.length / 2.0, 1.0);
    return (score, found);
  }

  double _analyzeGrammar(String body) {
    if (body.isEmpty) return 0.0;
    double anomalyScore = 0;

    // Excessive exclamation marks
    final exclamationCount = '!'.allMatches(body).length;
    if (exclamationCount > 5) anomalyScore += 0.3;

    // Excessive capitalization
    final upperCount = body
        .split('')
        .where((c) => c == c.toUpperCase() && c != c.toLowerCase())
        .length;
    final alphaCount = body
        .split('')
        .where((c) => c.toUpperCase() != c.toLowerCase())
        .length;
    if (alphaCount > 0 && upperCount / alphaCount > 0.4) anomalyScore += 0.3;

    // Very short body (potential lure to click link)
    if (body.length < 50 && body.contains(RegExp(r'https?://')))
      anomalyScore += 0.2;

    // Multiple consecutive dots or special chars
    if (RegExp(r'\.{3,}|!{3,}|\?{3,}').hasMatch(body)) anomalyScore += 0.2;

    return anomalyScore.clamp(0.0, 1.0);
  }

  bool _detectAuthorityImpersonation(String text, ParsedEmail email) {
    final displayName = email.senderDisplayName?.toLowerCase() ?? '';
    final combined = '$displayName $text';

    for (final pattern in _authorityPatterns) {
      if (combined.contains(pattern)) return true;
    }
    return false;
  }
}
