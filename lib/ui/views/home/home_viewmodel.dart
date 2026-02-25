import 'package:flutter/material.dart';
import 'package:inline_logger/inline_logger.dart';

import 'package:stacked/stacked.dart';
import 'package:trustprobe_ai/app/app.locator.dart';
import 'package:trustprobe_ai/services/device_id_service.dart';
import 'package:trustprobe_ai/services/phishing_service.dart';
import 'package:trustprobe_ai/services/email_phishing_service.dart';
import 'package:trustprobe_ai/services/firestore_service.dart';
import 'package:trustprobe_ai/models/scan_result.dart';
import 'package:trustprobe_ai/models/email_scan_result.dart';

/// HomeViewModel - Business logic for the home screen
///
/// Manages URL and email analysis, tab state, and Firestore operations
class HomeViewModel extends BaseViewModel {
  final _phishingService = locator<PhishingService>();
  final _emailPhishingService = locator<EmailPhishingService>();
  final _firestoreService = locator<FirestoreService>();
  final _deviceIdService = locator<DeviceIdService>();

  // ──── Tab state ────
  int _selectedTab = 0;
  int get selectedTab => _selectedTab;

  // ──── TextField controllers ────
  final urlController = TextEditingController();
  final emailController = TextEditingController();

  void setSelectedTab(int index) {
    _selectedTab = index;
    // Clear both controllers to avoid stale text
    urlController.clear();
    emailController.clear();
    _urlInput = '';
    _emailInput = '';
    _errorMessage = null;
    _emailErrorMessage = null;
    notifyListeners();
  }

  @override
  void dispose() {
    urlController.dispose();
    emailController.dispose();
    super.dispose();
  }

  // ──── URL Scan state ────
  String _urlInput = '';
  ScanResult? _currentResult;
  String? _errorMessage;

  String get urlInput => _urlInput;
  ScanResult? get currentResult => _currentResult;
  String? get errorMessage => _errorMessage;
  bool get hasResult => _currentResult != null;
  @override
  bool get hasError => _errorMessage != null;

  late final Stream<List<ScanResult>> previousScans = _firestoreService
      .getPreviousScans(deviceId: _deviceIdService.deviceId);

  void updateUrlInput(String value) {
    _urlInput = value;
    _errorMessage = null;
    notifyListeners();
  }

  Future<void> analyzeUrl() async {
    _currentResult = null;
    _errorMessage = null;

    if (_urlInput.trim().isEmpty) {
      _errorMessage = 'Please enter a URL to analyze';
      notifyListeners();
      return;
    }

    setBusy(true);
    notifyListeners();

    try {
      final result = await _phishingService.analyzeUrl(_urlInput);
      _currentResult = result.copyWith(deviceId: _deviceIdService.deviceId);

      _firestoreService
          .saveScanResult(_currentResult!)
          .timeout(
            const Duration(seconds: 2),
            onTimeout: () {
              Logger.warning('Firestore save timed out', 'HomeViewModel');
            },
          )
          .catchError((error) {
            Logger.error('Firestore save error: $error', 'HomeViewModel');
          });

      _errorMessage = null;
    } catch (e) {
      _errorMessage = 'Failed to analyze URL: ${e.toString()}';
      _currentResult = null;
    } finally {
      setBusy(false);
      notifyListeners();
    }
  }

  void clearResult() {
    _currentResult = null;
    _urlInput = '';
    _errorMessage = null;
    notifyListeners();
  }

  void showPreviousScan(ScanResult result) {
    _currentResult = result;
    _urlInput = result.url;
    _errorMessage = null;
    notifyListeners();
  }

  // ──── Email Scan state ────
  String _emailInput = '';
  EmailScanResult? _currentEmailResult;
  String? _emailErrorMessage;

  String get emailInput => _emailInput;
  EmailScanResult? get currentEmailResult => _currentEmailResult;
  String? get emailErrorMessage => _emailErrorMessage;
  bool get hasEmailResult => _currentEmailResult != null;
  bool get hasEmailError => _emailErrorMessage != null;

  // No email history — emails are never saved (privacy)

  void updateEmailInput(String value) {
    _emailInput = value;
    _emailErrorMessage = null;
    notifyListeners();
  }

  Future<void> analyzeEmail() async {
    _currentEmailResult = null;
    _emailErrorMessage = null;

    if (_emailInput.trim().isEmpty) {
      _emailErrorMessage = 'Please paste email content to analyze';
      notifyListeners();
      return;
    }

    setBusy(true);
    notifyListeners();

    try {
      final result = await _emailPhishingService.analyzeEmail(_emailInput);
      _currentEmailResult = result.copyWith(
        deviceId: _deviceIdService.deviceId,
      );

      // Emails are NOT saved to Firestore — privacy first

      _emailErrorMessage = null;
    } catch (e) {
      _emailErrorMessage = 'Failed to analyze email: ${e.toString()}';
      _currentEmailResult = null;
    } finally {
      setBusy(false);
      notifyListeners();
    }
  }

  void clearEmailResult() {
    _currentEmailResult = null;
    _emailInput = '';
    _emailErrorMessage = null;
    notifyListeners();
  }

  void showPreviousEmailScan(EmailScanResult result) {
    _currentEmailResult = result;
    _emailErrorMessage = null;
    notifyListeners();
  }
}
