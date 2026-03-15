import 'package:flutter_test/flutter_test.dart';
import 'package:trustprobe_ai/services/phishing_service.dart';

void main() {
  group('PhishingService Sample Tests', () {
    late PhishingService phishingService;

    setUp(() {
      phishingService = PhishingService();
    });

    test('Analyze a known safe URL (google.com)', () async {
      final result = await phishingService.analyzeUrl('https://google.com');
      
      expect(result.classification, equals('Safe'));
      expect(result.riskScore, lessThan(40));
    });

    test('Analyze a suspicious IP-based URL', () async {
      final result = await phishingService.analyzeUrl('http://192.168.1.1/login');
      
      expect(result.classification, isNot(equals('Safe')));
      expect(result.riskScore, greaterThan(30));
    });

    test('Check if multi-modal data is populated', () async {
      final result = await phishingService.analyzeUrl('https://example.com');
      
      expect(result.hasMultiModalData, isTrue);
      expect(result.modalityScores.length, greaterThan(0));
    });
  });
}
