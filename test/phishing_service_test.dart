import 'package:flutter_test/flutter_test.dart';
import 'package:trustprobe_ai/services/phishing_service.dart';
import 'package:trustprobe_ai/services/multi_modal_engine.dart';
import 'package:trustprobe_ai/services/url_feature_extractor.dart';
import 'package:trustprobe_ai/services/sequential_analyzer.dart';
import 'package:trustprobe_ai/services/host_analysis_service.dart';
import 'package:trustprobe_ai/services/benchmark_service.dart';
import 'package:trustprobe_ai/models/scan_result.dart';

void main() {
  group('PhishingService Multi-Modal Tests', () {
    late PhishingService phishingService;

    setUp(() {
      phishingService = PhishingService();
    });

    test('Safe URL - google.com', () async {
      final result = await phishingService.analyzeUrl('google.com');

      expect(result.riskScore, lessThan(40));
      expect(result.classification, equals('Safe'));
      expect(result.reason, contains('trusted domain'));
      expect(result.featureCount, greaterThan(0));
      expect(result.modalityScores, isNotEmpty);
    });

    test('Safe URL - facebook.com', () async {
      final result = await phishingService.analyzeUrl('facebook.com');

      expect(result.riskScore, lessThan(40));
      expect(result.classification, equals('Safe'));
      expect(result.hasMultiModalData, isTrue);
    });

    test('Malicious URL - with bank keyword', () async {
      final result = await phishingService.analyzeUrl(
        'secure-bank-login.example.com',
      );

      expect(result.riskScore, greaterThan(30));
      expect(result.classification, isIn(['Suspicious', 'Malicious']));
      expect(result.featureCount, greaterThan(50));
    });

    test('Malicious URL - with paypal keyword and http', () async {
      final result = await phishingService.analyzeUrl(
        'http://paypal-verify.suspicious.com',
      );

      expect(result.riskScore, greaterThan(30));
      expect(result.classification, isNot(equals('Safe')));
    });

    test('Malicious URL - IP address', () async {
      final result = await phishingService.analyzeUrl(
        'http://192.168.1.1/login',
      );

      expect(result.riskScore, greaterThan(30));
      expect(result.classification, isNot(equals('Safe')));
    });

    test('Invalid URL format', () async {
      final result = await phishingService.analyzeUrl('not a valid url!!!');

      expect(result.riskScore, equals(100));
      expect(result.classification, equals('Malicious'));
      expect(result.reason, equals('Invalid URL format'));
    });

    test('HTTPS vs HTTP - HTTPS should be safer', () async {
      final httpsResult = await phishingService.analyzeUrl(
        'https://example.com',
      );
      final httpResult = await phishingService.analyzeUrl('http://example.com');

      expect(httpResult.riskScore, greaterThan(httpsResult.riskScore));
    });

    test('Multi-modal data is present in results', () async {
      final result = await phishingService.analyzeUrl('https://example.com');

      expect(result.hasMultiModalData, isTrue);
      expect(result.modalityScores, isNotEmpty);
      expect(result.modalityScores.length, equals(5));
      expect(result.featureCount, equals(55));
    });
  });

  group('Multi-Modal Engine Tests', () {
    late MultiModalEngine engine;

    setUp(() {
      engine = MultiModalEngine();
    });

    test('Trusted domain gets low score', () {
      final url = 'https://www.google.com';
      final parsedUrl = Uri.parse(url);
      final result = engine.analyze(url, parsedUrl);

      expect(result.riskScore, lessThanOrEqualTo(30));
      expect(result.classification, equals('Safe'));
      expect(result.modalityScores.length, equals(5));
    });

    test('Phishing URL gets high score', () {
      final url = 'http://paypal-login-verification.tk/signin';
      final parsedUrl = Uri.parse(url);
      final result = engine.analyze(url, parsedUrl);

      expect(result.riskScore, greaterThan(30));
      expect(result.classification, isNot(equals('Safe')));
    });

    test('IP-based URL gets flagged', () {
      final url = 'http://192.168.1.1/admin/login';
      final parsedUrl = Uri.parse(url);
      final result = engine.analyze(url, parsedUrl);

      expect(result.riskScore, greaterThan(30));
    });

    test('Feature count is correct (55 total)', () {
      final url = 'https://example.com';
      final parsedUrl = Uri.parse(url);
      final result = engine.analyze(url, parsedUrl);

      expect(result.featureSet.totalFeatureCount, equals(55));
    });
  });

  group('URL Feature Extractor (CNN) Tests', () {
    late UrlFeatureExtractor extractor;

    setUp(() {
      extractor = UrlFeatureExtractor();
    });

    test('Extracts correct feature count', () {
      final url = 'https://www.google.com';
      final features = extractor.extract(url, Uri.parse(url));

      expect(features.featureCount, equals(25));
    });

    test('Entropy is higher for random URLs', () {
      final normalUrl = 'https://www.google.com';
      final randomUrl = 'https://xkjf7823ksd.tk/signin';

      final normalFeatures = extractor.extract(normalUrl, Uri.parse(normalUrl));
      final randomFeatures = extractor.extract(randomUrl, Uri.parse(randomUrl));

      expect(randomFeatures.entropy, greaterThan(normalFeatures.entropy));
    });

    test('Detects at symbol', () {
      final url = 'http://www.google.com@evil.tk/login';
      final features = extractor.extract(url, Uri.parse(url));

      expect(features.atSymbolCount, greaterThan(0));
    });
  });

  group('Sequential Analyzer (LSTM) Tests', () {
    late SequentialAnalyzer analyzer;

    setUp(() {
      analyzer = SequentialAnalyzer();
    });

    test('Extracts correct feature count', () {
      final url = 'https://www.google.com';
      final features = analyzer.analyze(url, Uri.parse(url));

      expect(features.featureCount, equals(8));
    });

    test('Random domain has higher anomaly', () {
      final normalUrl = 'https://www.google.com';
      final randomUrl = 'https://xkjf7823ksd.tk/signin';

      final normalFeatures = analyzer.analyze(normalUrl, Uri.parse(normalUrl));
      final randomFeatures = analyzer.analyze(randomUrl, Uri.parse(randomUrl));

      expect(
        randomFeatures.bigramAnomalyScore,
        greaterThan(normalFeatures.bigramAnomalyScore),
      );
    });
  });

  group('Host Analysis Tests', () {
    late HostAnalysisService hostService;

    setUp(() {
      hostService = HostAnalysisService();
    });

    test('Trusted domain is detected', () {
      final features = hostService.analyze(Uri.parse('https://www.google.com'));
      expect(features.isTrustedDomain, isTrue);
    });

    test('Brand impersonation is detected', () {
      final features = hostService.analyze(
        Uri.parse('http://paypal-login.tk/verify'),
      );
      expect(features.brandImpersonationScore, greaterThan(0.5));
      expect(features.impersonatedBrand, equals('paypal'));
    });

    test('High-risk TLD is scored', () {
      final features = hostService.analyze(Uri.parse('http://example.tk'));
      expect(features.tldRiskScore, greaterThan(0.8));
    });

    test('IP address is detected', () {
      final features = hostService.analyze(
        Uri.parse('http://192.168.1.1/login'),
      );
      expect(features.isIpAddress, isTrue);
    });
  });

  group('ScanResult Model Tests', () {
    test('Risk color - low risk', () {
      final result = ScanResult(
        url: 'google.com',
        riskScore: 25,
        classification: 'Safe',
        reason: 'Trusted domain',
        timestamp: DateTime.now(),
      );

      expect(result.riskColor, equals('green'));
      expect(result.riskLevel, equals('Low Risk'));
    });

    test('Risk color - medium risk', () {
      final result = ScanResult(
        url: 'example.com',
        riskScore: 55,
        classification: 'Suspicious',
        reason: 'Some risks',
        timestamp: DateTime.now(),
      );

      expect(result.riskColor, equals('yellow'));
      expect(result.riskLevel, equals('Medium Risk'));
    });

    test('Risk color - high risk', () {
      final result = ScanResult(
        url: 'malicious.com',
        riskScore: 85,
        classification: 'Malicious',
        reason: 'Multiple risks',
        timestamp: DateTime.now(),
      );

      expect(result.riskColor, equals('red'));
      expect(result.riskLevel, equals('High Risk'));
    });

    test('toMap and fromFirestore with multi-modal data', () {
      final original = ScanResult(
        url: 'test.com',
        riskScore: 50,
        classification: 'Suspicious',
        reason: 'Test reason',
        timestamp: DateTime(2024, 1, 1, 12, 0),
        modalityScores: {
          'CNN Character Analysis': 40.0,
          'Host & Domain Analysis': 60.0,
        },
        modalityExplanations: {'CNN Character Analysis': 'Test explanation'},
        featureCount: 55,
      );

      final map = original.toMap();
      final reconstructed = ScanResult.fromFirestore(map);

      expect(reconstructed.url, equals(original.url));
      expect(reconstructed.riskScore, equals(original.riskScore));
      expect(reconstructed.classification, equals(original.classification));
      expect(reconstructed.reason, equals(original.reason));
      expect(reconstructed.featureCount, equals(55));
      expect(reconstructed.modalityScores.length, equals(2));
      expect(reconstructed.hasMultiModalData, isTrue);
    });
  });

  group('Benchmark Tests', () {
    late BenchmarkService benchmarkService;

    setUp(() {
      benchmarkService = BenchmarkService();
    });

    test('Benchmark achieves >= 95% accuracy', () {
      final result = benchmarkService.evaluate();

      print('Benchmark Results:');
      print('  Total Samples: ${result.totalSamples}');
      print('  Accuracy: ${result.accuracyPercent}');
      print('  Precision: ${(result.precision * 100).toStringAsFixed(1)}%');
      print('  Recall: ${(result.recall * 100).toStringAsFixed(1)}%');
      print('  F1 Score: ${(result.f1Score * 100).toStringAsFixed(1)}%');
      print('  True Positives: ${result.truePositives}');
      print('  True Negatives: ${result.trueNegatives}');
      print('  False Positives: ${result.falsePositives}');
      print('  False Negatives: ${result.falseNegatives}');

      if (result.errors.isNotEmpty) {
        print('  Errors (${result.errors.length}):');
        for (final error in result.errors) {
          print('    $error');
        }
      }

      final perSource = result.perSourceAccuracy;
      print('  Per-source accuracy:');
      for (final entry in perSource.entries) {
        print('    ${entry.key}: ${(entry.value * 100).toStringAsFixed(1)}%');
      }

      expect(
        result.accuracy,
        greaterThanOrEqualTo(0.95),
        reason: 'Expected >= 95% accuracy, got ${result.accuracyPercent}',
      );
    });

    test('Benchmark has sufficient dataset size', () {
      final result = benchmarkService.evaluate();

      expect(result.totalSamples, greaterThan(180));
      expect(result.phishingSamples, greaterThan(80));
      expect(result.safeSamples, greaterThan(80));
    });
  });
}
