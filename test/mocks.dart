import 'package:trustprobe_ai/services/firestore_service.dart';
import 'package:trustprobe_ai/services/device_id_service.dart';
import 'package:trustprobe_ai/services/phishing_service.dart';
import 'package:trustprobe_ai/models/scan_result.dart';
import 'package:trustprobe_ai/models/email_scan_result.dart';

class MockFirestoreService implements FirestoreService {
  @override
  Future<void> saveScanResult(ScanResult result) async {}

  @override
  Stream<List<ScanResult>> getPreviousScans({
    required String deviceId,
    int limit = 50,
  }) => Stream.value([]);

  @override
  Future<void> saveEmailScanResult(EmailScanResult result) async {}

  @override
  Stream<List<EmailScanResult>> getPreviousEmailScans({
    required String deviceId,
    int limit = 50,
  }) => Stream.value([]);

  @override
  Future<int> getScanCount() async => 0;

  @override
  Future<void> deleteOldScans({int daysOld = 30}) async {}
}

class MockDeviceIdService implements DeviceIdService {
  @override
  String get deviceId => 'test-device-id';

  @override
  Future<void> initialize() async {}
}

class MockPhishingService implements PhishingService {
  @override
  Future<ScanResult> analyzeUrl(String url, {String? deviceId}) async {
    return ScanResult(
      url: url,
      riskScore: 10,
      classification: 'Safe',
      reason: 'Test scan',
      timestamp: DateTime.now(),
      deviceId: deviceId ?? 'test',
    );
  }
}
