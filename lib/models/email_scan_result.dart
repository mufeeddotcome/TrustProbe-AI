/// EmailScanResult — Result from multi-modal email phishing analysis
class EmailScanResult {
  /// Original sender email address
  final String? senderEmail;

  /// Email subject line
  final String? subject;

  /// Full email body text (for display/reference)
  final String bodyPreview;

  /// Overall phishing risk score (0-100)
  final int riskScore;

  /// Classification: Safe, Suspicious, Malicious
  final String classification;

  /// Human-readable explanation of findings
  final String reason;

  /// Timestamp of the scan
  final DateTime timestamp;

  /// Per-modality risk scores (0-100)
  final Map<String, double> modalityScores;

  /// Per-modality human-readable explanations
  final Map<String, String> modalityExplanations;

  /// Total features analyzed
  final int featureCount;

  /// Number of embedded URLs found
  final int embeddedUrlCount;

  /// Highest risk embedded URL (if any)
  final String? highestRiskUrl;

  /// Risk score of the highest risk URL
  final int? highestRiskUrlScore;

  /// AI-generated analysis text
  final String? aiAnalysis;

  /// Device ID for per-device history
  final String? deviceId;

  /// Scan type identifier
  final String scanType;

  const EmailScanResult({
    required this.senderEmail,
    required this.subject,
    required this.bodyPreview,
    required this.riskScore,
    required this.classification,
    required this.reason,
    required this.timestamp,
    this.modalityScores = const {},
    this.modalityExplanations = const {},
    this.featureCount = 0,
    this.embeddedUrlCount = 0,
    this.highestRiskUrl,
    this.highestRiskUrlScore,
    this.aiAnalysis,
    this.deviceId,
    this.scanType = 'email',
  });

  EmailScanResult copyWith({
    String? senderEmail,
    String? subject,
    String? bodyPreview,
    int? riskScore,
    String? classification,
    String? reason,
    DateTime? timestamp,
    Map<String, double>? modalityScores,
    Map<String, String>? modalityExplanations,
    int? featureCount,
    int? embeddedUrlCount,
    String? highestRiskUrl,
    int? highestRiskUrlScore,
    String? aiAnalysis,
    String? deviceId,
  }) => EmailScanResult(
    senderEmail: senderEmail ?? this.senderEmail,
    subject: subject ?? this.subject,
    bodyPreview: bodyPreview ?? this.bodyPreview,
    riskScore: riskScore ?? this.riskScore,
    classification: classification ?? this.classification,
    reason: reason ?? this.reason,
    timestamp: timestamp ?? this.timestamp,
    modalityScores: modalityScores ?? this.modalityScores,
    modalityExplanations: modalityExplanations ?? this.modalityExplanations,
    featureCount: featureCount ?? this.featureCount,
    embeddedUrlCount: embeddedUrlCount ?? this.embeddedUrlCount,
    highestRiskUrl: highestRiskUrl ?? this.highestRiskUrl,
    highestRiskUrlScore: highestRiskUrlScore ?? this.highestRiskUrlScore,
    aiAnalysis: aiAnalysis ?? this.aiAnalysis,
    deviceId: deviceId ?? this.deviceId,
  );

  factory EmailScanResult.fromFirestore(Map<String, dynamic> data) =>
      EmailScanResult(
        senderEmail: data['senderEmail'] as String?,
        subject: data['subject'] as String?,
        bodyPreview: data['bodyPreview'] as String? ?? '',
        riskScore: data['riskScore'] as int,
        classification: data['classification'] as String,
        reason: data['reason'] as String,
        timestamp: DateTime.parse(data['timestamp'] as String),
        modalityScores:
            (data['modalityScores'] as Map<String, dynamic>?)?.map(
              (k, v) => MapEntry(k, (v as num).toDouble()),
            ) ??
            {},
        modalityExplanations:
            (data['modalityExplanations'] as Map<String, dynamic>?)?.map(
              (k, v) => MapEntry(k, v as String),
            ) ??
            {},
        featureCount: data['featureCount'] as int? ?? 0,
        embeddedUrlCount: data['embeddedUrlCount'] as int? ?? 0,
        highestRiskUrl: data['highestRiskUrl'] as String?,
        highestRiskUrlScore: data['highestRiskUrlScore'] as int?,
        aiAnalysis: data['aiAnalysis'] as String?,
        deviceId: data['deviceId'] as String?,
        scanType: data['scanType'] as String? ?? 'email',
      );

  Map<String, dynamic> toMap() => {
    'senderEmail': senderEmail,
    'subject': subject,
    'bodyPreview': bodyPreview.length > 500
        ? bodyPreview.substring(0, 500)
        : bodyPreview,
    'riskScore': riskScore,
    'classification': classification,
    'reason': reason,
    'timestamp': timestamp.toIso8601String(),
    if (modalityScores.isNotEmpty) 'modalityScores': modalityScores,
    if (modalityExplanations.isNotEmpty)
      'modalityExplanations': modalityExplanations,
    if (featureCount > 0) 'featureCount': featureCount,
    'embeddedUrlCount': embeddedUrlCount,
    if (highestRiskUrl != null) 'highestRiskUrl': highestRiskUrl,
    if (highestRiskUrlScore != null) 'highestRiskUrlScore': highestRiskUrlScore,
    if (aiAnalysis != null) 'aiAnalysis': aiAnalysis,
    if (deviceId != null) 'deviceId': deviceId,
    'scanType': 'email',
  };

  String get riskColor => switch (riskScore) {
    <= 30 => 'green',
    <= 60 => 'yellow',
    _ => 'red',
  };

  String get riskLevel => switch (riskScore) {
    <= 30 => 'Low Risk',
    <= 60 => 'Medium Risk',
    _ => 'High Risk',
  };

  bool get hasMultiModalData => modalityScores.isNotEmpty;

  @override
  String toString() =>
      'EmailScanResult(sender: $senderEmail, riskScore: $riskScore, classification: $classification)';
}
