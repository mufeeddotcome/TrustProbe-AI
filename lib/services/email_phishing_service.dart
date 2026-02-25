import 'package:inline_logger/inline_logger.dart';

import 'email_parser.dart';
import 'email_multi_modal_engine.dart';
import 'ai_service.dart';
import '../app/app.locator.dart';
import '../models/email_scan_result.dart';

/// EmailPhishingService — Top-level orchestrator for email analysis
///
/// Parses email → runs multi-modal engine → calls AI service →
/// returns [EmailScanResult].
class EmailPhishingService {
  final EmailParser _parser;
  final EmailMultiModalEngine _engine;
  final AiService _aiService;

  EmailPhishingService({
    EmailParser? parser,
    EmailMultiModalEngine? engine,
    AiService? aiService,
  }) : _parser = parser ?? EmailParser(),
       _engine = engine ?? EmailMultiModalEngine(),
       _aiService = aiService ?? locator<AiService>();

  /// Analyze raw email text for phishing
  Future<EmailScanResult> analyzeEmail(String rawEmail) async {
    if (rawEmail.trim().isEmpty) {
      return EmailScanResult(
        senderEmail: null,
        subject: null,
        bodyPreview: '',
        riskScore: 0,
        classification: 'Safe',
        reason: 'No email content provided',
        timestamp: DateTime.now(),
      );
    }

    // Parse the email
    final parsed = _parser.parse(rawEmail);

    // Run multi-modal analysis
    final result = _engine.analyze(parsed);

    // Generate body preview (first 200 chars)
    final preview = parsed.body.length > 200
        ? '${parsed.body.substring(0, 200)}...'
        : parsed.body;

    // Build the base result
    var scanResult = EmailScanResult(
      senderEmail: parsed.senderEmail,
      subject: parsed.subject,
      bodyPreview: preview,
      riskScore: result.riskScore,
      classification: result.classification,
      reason: result.reason,
      timestamp: DateTime.now(),
      modalityScores: result.modalityScores,
      modalityExplanations: result.modalityExplanations,
      featureCount: result.featureSet.totalFeatureCount,
      embeddedUrlCount: parsed.embeddedUrls.length,
      highestRiskUrl: result.highestRiskUrl,
      highestRiskUrlScore: result.highestRiskUrlScore,
    );

    // Call AI service for enhanced analysis (non-blocking)
    try {
      final aiResult = await _aiService.analyzeUrl(
        url:
            'EMAIL: ${parsed.senderEmail ?? "unknown"} | Subject: ${parsed.subject ?? "none"}',
        heuristicScore: result.riskScore,
        heuristicClassification: result.classification,
        heuristicReason: result.reason,
        featureCount: result.featureSet.totalFeatureCount,
        modalityScores: {
          for (final entry in result.modalityScores.entries)
            entry.key: entry.value / 100.0,
        },
      );

      if (aiResult != null) {
        scanResult = scanResult.copyWith(
          aiAnalysis: aiResult.toFormattedString(),
        );
      }
    } catch (e) {
      Logger.warning(
        'AI analysis failed for email: $e',
        'EmailPhishingService',
      );
    }

    return scanResult;
  }
}
