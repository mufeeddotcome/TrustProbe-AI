import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:inline_logger/inline_logger.dart';

import '../models/scan_result.dart';
import '../models/email_scan_result.dart';

/// FirestoreService - Manages Firebase Firestore operations
///
/// Handles saving and retrieving URL scan results from Firestore,
/// scoped by device ID for per-device history.
class FirestoreService {
  final _firestore = FirebaseFirestore.instance;

  static const _collectionName = 'url_scans';

  /// Save a scan result to Firestore
  Future<void> saveScanResult(ScanResult result) async {
    try {
      await _firestore.collection(_collectionName).add(result.toMap());
    } catch (e) {
      Logger.error('Error saving scan result: $e', 'FirestoreService');
    }
  }

  /// Get previous scan results as a stream, filtered by device ID
  /// Returns empty stream if Firebase is not configured
  Stream<List<ScanResult>> getPreviousScans({
    required String deviceId,
    int limit = 50,
  }) {
    try {
      return _firestore
          .collection(_collectionName)
          .where('deviceId', isEqualTo: deviceId)
          .orderBy('timestamp', descending: true)
          .limit(limit)
          .snapshots()
          .timeout(
            const Duration(seconds: 3),
            onTimeout: (sink) => sink.close(),
          )
          .handleError((error) {
            Logger.error('Firestore error: $error', 'FirestoreService');
          })
          .map(
            (snapshot) => snapshot.docs
                .map((doc) => ScanResult.fromFirestore(doc.data()))
                .toList(),
          );
    } catch (e) {
      Logger.error('Error setting up Firestore stream: $e', 'FirestoreService');
      return Stream.value([]);
    }
  }

  // ──── Email Scans ────

  static const _emailCollectionName = 'email_scans';

  /// Save an email scan result to Firestore
  Future<void> saveEmailScanResult(EmailScanResult result) async {
    try {
      await _firestore.collection(_emailCollectionName).add(result.toMap());
    } catch (e) {
      Logger.error('Error saving email scan: $e', 'FirestoreService');
    }
  }

  /// Get previous email scan results as a stream
  Stream<List<EmailScanResult>> getPreviousEmailScans({
    required String deviceId,
    int limit = 50,
  }) {
    try {
      return _firestore
          .collection(_emailCollectionName)
          .where('deviceId', isEqualTo: deviceId)
          .orderBy('timestamp', descending: true)
          .limit(limit)
          .snapshots()
          .timeout(
            const Duration(seconds: 3),
            onTimeout: (sink) => sink.close(),
          )
          .handleError((error) {
            Logger.error('Email scan stream error: $error', 'FirestoreService');
          })
          .map(
            (snapshot) => snapshot.docs
                .map((doc) => EmailScanResult.fromFirestore(doc.data()))
                .toList(),
          );
    } catch (e) {
      Logger.error(
        'Error setting up email scan stream: $e',
        'FirestoreService',
      );
      return Stream.value([]);
    }
  }

  /// Get scan count for analytics
  Future<int> getScanCount() async {
    try {
      final snapshot = await _firestore
          .collection(_collectionName)
          .count()
          .get();
      return snapshot.count ?? 0;
    } catch (e) {
      Logger.error('Error getting scan count: $e', 'FirestoreService');
      return 0;
    }
  }

  /// Delete old scans (cleanup method)
  Future<void> deleteOldScans({int daysOld = 30}) async {
    try {
      final cutoffDate = DateTime.now().subtract(Duration(days: daysOld));
      final snapshot = await _firestore
          .collection(_collectionName)
          .where('timestamp', isLessThan: cutoffDate.toIso8601String())
          .get();

      final batch = _firestore.batch();
      for (final doc in snapshot.docs) {
        batch.delete(doc.reference);
      }
      await batch.commit();
    } catch (e) {
      Logger.error('Error deleting old scans: $e', 'FirestoreService');
      rethrow;
    }
  }
}
