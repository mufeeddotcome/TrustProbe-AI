import 'package:inline_logger/inline_logger.dart';

import '../config/ai_config.dart';

import 'dart:convert';

import 'package:http/http.dart' as http;

/// AiService - Open-source LLM integration via Groq API
///
/// Uses Llama 3.3 70B (open-source) to provide intelligent,
/// detailed phishing threat analysis beyond rule-based heuristics.
/// Receives multi-modal feature analysis context for enhanced accuracy.
class AiService {
  /// System prompt that guides the LLM for phishing analysis
  static const _systemPrompt = '''
You are TrustProbe AI, an expert cybersecurity analyst specializing in phishing URL detection.
You are part of a multi-modal AI phishing detection system that combines:
1. CNN-based character-level URL analysis (25+ lexical features including Shannon entropy, character distributions, n-gram patterns)
2. LSTM-based sequential pattern analysis (8 features including character transition anomalies, bigram analysis, positional distribution)
3. Host and domain attribute analysis (10 features including TLD reputation, brand impersonation, domain age estimation)
4. SSL/security attribute analysis (5 features including HTTPS verification, certificate indicators)
5. Content analysis (7 features including login page detection, data exfiltration patterns)

When given a URL, its multi-modal risk data, and per-modality scores, provide a detailed security analysis.

You MUST respond in valid JSON format with exactly these fields:
{
  "threatSummary": "A concise 1-2 sentence summary of the threat level and key finding",
  "riskFactors": ["factor1", "factor2", "factor3"],
  "recommendation": "A clear, actionable recommendation for the user",
  "confidenceLevel": "high|medium|low"
}

Guidelines:
- For SAFE URLs: Explain why the domain is trustworthy, mention SSL, established reputation
- For SUSPICIOUS URLs: Identify specific red flags, explain social engineering tactics used
- For MALICIOUS URLs: Warn clearly about the dangers, explain phishing techniques detected
- Always provide 2-5 specific risk factors
- Keep threatSummary under 100 words
- Keep recommendation practical and user-friendly
- Be specific about which phishing techniques are being used (typosquatting, homograph attacks, brand impersonation, etc.)
- Reference the multi-modal analysis components (CNN character analysis, LSTM sequential patterns, host attributes) in your assessment
- Consider the domain age implications, SSL certificate issues, and URL obfuscation techniques
''';

  /// Analyze a URL using the open-source LLM.
  /// Returns a parsed [AiAnalysisResult] or null if the AI call fails.
  Future<AiAnalysisResult?> analyzeUrl({
    required String url,
    required int heuristicScore,
    required String heuristicClassification,
    required String heuristicReason,
    int featureCount = 0,
    Map<String, double>? modalityScores,
  }) async {
    if (!AiConfig.isConfigured) {
      Logger.info(
        'Groq API key not configured. Skipping AI analysis.',
        'AiService',
      );
      return null;
    }

    try {
      final modalityContext = modalityScores != null
          ? modalityScores.entries
                .map(
                  (e) => '  - ${e.key}: ${(e.value * 100).toStringAsFixed(0)}%',
                )
                .join('\n')
          : 'Not available';

      final userPrompt =
          '''
Analyze this URL for phishing risk:

URL: $url
Multi-Modal Risk Score: $heuristicScore/100
Classification: $heuristicClassification
Features Analyzed: $featureCount across 5 modalities

Per-Modality Scores:
$modalityContext

Detection Findings: $heuristicReason

Provide your detailed security analysis in JSON format, referencing the multi-modal analysis components.
''';

      final response = await http
          .post(
            Uri.parse(AiConfig.baseUrl),
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Bearer ${AiConfig.groqApiKey}',
            },
            body: jsonEncode({
              'model': AiConfig.model,
              'messages': [
                {'role': 'system', 'content': _systemPrompt},
                {'role': 'user', 'content': userPrompt},
              ],
              'max_tokens': AiConfig.maxTokens,
              'temperature': 0.3,
              'response_format': {'type': 'json_object'},
            }),
          )
          .timeout(Duration(seconds: AiConfig.timeoutSeconds));

      if (response.statusCode == 200) {
        final content =
            (jsonDecode(response.body)['choices'] as List?)
                    ?.firstOrNull?['message']?['content']
                as String?;
        return content != null ? _parseAiResponse(content) : null;
      }

      Logger.warning(
        'API returned status ${response.statusCode}: ${response.body}',
        'AiService',
      );
    } catch (e) {
      Logger.error('Error during analysis - $e', 'AiService');
    }

    return null;
  }

  /// Parse the LLM's JSON response into a structured result
  AiAnalysisResult? _parseAiResponse(String content) {
    try {
      final json = jsonDecode(content) as Map<String, dynamic>;
      return AiAnalysisResult.fromMap(json);
    } catch (e) {
      Logger.error('Failed to parse AI response - $e', 'AiService');
      return null;
    }
  }
}

/// Structured result from AI analysis
class AiAnalysisResult {
  final String threatSummary;
  final List<String> riskFactors;
  final String recommendation;
  final String confidenceLevel;

  const AiAnalysisResult({
    required this.threatSummary,
    required this.riskFactors,
    required this.recommendation,
    required this.confidenceLevel,
  });

  factory AiAnalysisResult.fromMap(Map<String, dynamic> map) =>
      AiAnalysisResult(
        threatSummary:
            map['threatSummary'] as String? ?? 'Analysis unavailable',
        riskFactors:
            (map['riskFactors'] as List<dynamic>?)
                ?.map((e) => e.toString())
                .toList() ??
            [],
        recommendation:
            map['recommendation'] as String? ??
            'Exercise caution with unfamiliar URLs.',
        confidenceLevel: map['confidenceLevel'] as String? ?? 'medium',
      );

  /// Convert to a single formatted string for storage
  String toFormattedString() {
    final buffer = StringBuffer()
      ..writeln('AI Threat Summary: $threatSummary')
      ..writeln()
      ..writeln('Risk Factors:');
    for (final factor in riskFactors) {
      buffer.writeln('• $factor');
    }
    buffer
      ..writeln()
      ..writeln('Recommendation: $recommendation')
      ..writeln('Confidence: $confidenceLevel');
    return buffer.toString();
  }

  /// Create from formatted storage string
  static AiAnalysisResult? fromFormattedString(String? formatted) {
    if (formatted == null || formatted.isEmpty) return null;

    try {
      final lines = formatted.split('\n');
      var threatSummary = '';
      final riskFactors = <String>[];
      var recommendation = '';
      var confidenceLevel = 'medium';
      var inRiskFactors = false;

      for (final line in lines) {
        if (line.startsWith('AI Threat Summary: ')) {
          threatSummary = line.substring('AI Threat Summary: '.length);
          inRiskFactors = false;
        } else if (line == 'Risk Factors:') {
          inRiskFactors = true;
        } else if (line.startsWith('• ') && inRiskFactors) {
          riskFactors.add(line.substring(2));
        } else if (line.startsWith('Recommendation: ')) {
          recommendation = line.substring('Recommendation: '.length);
          inRiskFactors = false;
        } else if (line.startsWith('Confidence: ')) {
          confidenceLevel = line.substring('Confidence: '.length);
          inRiskFactors = false;
        }
      }

      if (threatSummary.isEmpty) return null;

      return AiAnalysisResult(
        threatSummary: threatSummary,
        riskFactors: riskFactors,
        recommendation: recommendation,
        confidenceLevel: confidenceLevel,
      );
    } catch (_) {
      return null;
    }
  }

  Map<String, dynamic> toMap() => {
    'threatSummary': threatSummary,
    'riskFactors': riskFactors,
    'recommendation': recommendation,
    'confidenceLevel': confidenceLevel,
  };
}
