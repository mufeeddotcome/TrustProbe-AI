class ScanResult {
  final String url;
  final int riskScore;
  final String classification;
  final String reason;
  final DateTime timestamp;
  final String? aiAnalysis;
  final String? deviceId;
  final Map<String, int> scoreBreakdown;

  /// Per-modality risk scores (0-100) from multi-modal analysis
  final Map<String, double> modalityScores;

  /// Per-modality human-readable explanations
  final Map<String, String> modalityExplanations;

  /// Total number of features extracted across all modalities
  final int featureCount;

  const ScanResult({
    required this.url,
    required this.riskScore,
    required this.classification,
    required this.reason,
    required this.timestamp,
    this.aiAnalysis,
    this.deviceId,
    this.scoreBreakdown = const {},
    this.modalityScores = const {},
    this.modalityExplanations = const {},
    this.featureCount = 0,
  });

  /// Create a copy with optional field overrides
  ScanResult copyWith({
    String? url,
    int? riskScore,
    String? classification,
    String? reason,
    DateTime? timestamp,
    String? aiAnalysis,
    String? deviceId,
    Map<String, int>? scoreBreakdown,
    Map<String, double>? modalityScores,
    Map<String, String>? modalityExplanations,
    int? featureCount,
  }) => ScanResult(
    url: url ?? this.url,
    riskScore: riskScore ?? this.riskScore,
    classification: classification ?? this.classification,
    reason: reason ?? this.reason,
    timestamp: timestamp ?? this.timestamp,
    aiAnalysis: aiAnalysis ?? this.aiAnalysis,
    deviceId: deviceId ?? this.deviceId,
    scoreBreakdown: scoreBreakdown ?? this.scoreBreakdown,
    modalityScores: modalityScores ?? this.modalityScores,
    modalityExplanations: modalityExplanations ?? this.modalityExplanations,
    featureCount: featureCount ?? this.featureCount,
  );

  /// Create ScanResult from Firestore DocumentSnapshot
  factory ScanResult.fromFirestore(Map<String, dynamic> data) => ScanResult(
    url: data['url'] as String,
    riskScore: data['riskScore'] as int,
    classification: data['classification'] as String,
    reason: data['reason'] as String,
    timestamp: DateTime.parse(data['timestamp'] as String),
    aiAnalysis: data['aiAnalysis'] as String?,
    deviceId: data['deviceId'] as String?,
    scoreBreakdown:
        (data['scoreBreakdown'] as Map<String, dynamic>?)?.map(
          (k, v) => MapEntry(k, v as int),
        ) ??
        {},
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
  );

  /// Convert ScanResult to Map for Firestore
  Map<String, dynamic> toMap() => {
    'url': url,
    'riskScore': riskScore,
    'classification': classification,
    'reason': reason,
    'timestamp': timestamp.toIso8601String(),
    if (aiAnalysis != null) 'aiAnalysis': aiAnalysis,
    if (deviceId != null) 'deviceId': deviceId,
    if (scoreBreakdown.isNotEmpty) 'scoreBreakdown': scoreBreakdown,
    if (modalityScores.isNotEmpty) 'modalityScores': modalityScores,
    if (modalityExplanations.isNotEmpty)
      'modalityExplanations': modalityExplanations,
    if (featureCount > 0) 'featureCount': featureCount,
  };

  /// Get color based on risk score
  String get riskColor => switch (riskScore) {
    <= 30 => 'green',
    <= 60 => 'yellow',
    _ => 'red',
  };

  /// Get risk level label
  String get riskLevel => switch (riskScore) {
    <= 30 => 'Low Risk',
    <= 60 => 'Medium Risk',
    _ => 'High Risk',
  };

  /// Whether multi-modal analysis data is available
  bool get hasMultiModalData => modalityScores.isNotEmpty;

  @override
  String toString() =>
      'ScanResult(url: $url, riskScore: $riskScore, classification: $classification, features: $featureCount)';
}
