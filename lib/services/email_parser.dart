/// EmailParser — Extracts structured data from raw email text
///
/// Handles both full email (with headers) and body-only input.
/// Extracts sender, reply-to, subject, body, and embedded URLs.
class EmailParser {
  /// URL regex pattern for extracting links from email body
  static final _urlPattern = RegExp(
    r'https?://[^\s<>"{}|\\^`\[\]]+',
    caseSensitive: false,
  );

  /// Email address regex
  static final _emailPattern = RegExp(
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
  );

  /// Parse raw email text into structured data
  ParsedEmail parse(String rawEmail) {
    final trimmed = rawEmail.trim();

    if (trimmed.isEmpty) {
      return ParsedEmail.empty();
    }

    // Detect if input has email headers
    final hasHeaders = _detectHeaders(trimmed);

    if (hasHeaders) {
      return _parseWithHeaders(trimmed);
    } else {
      return _parseBodyOnly(trimmed);
    }
  }

  /// Detect whether the input contains email headers
  bool _detectHeaders(String text) {
    final firstLines = text.split('\n').take(10).join('\n').toLowerCase();
    return firstLines.contains('from:') ||
        firstLines.contains('to:') ||
        firstLines.contains('subject:') ||
        firstLines.contains('date:') ||
        firstLines.contains('reply-to:') ||
        firstLines.contains('return-path:') ||
        firstLines.contains('received:') ||
        firstLines.contains('message-id:');
  }

  /// Parse email with headers
  ParsedEmail _parseWithHeaders(String raw) {
    // Split headers from body (double newline separator)
    final headerBodySplit = raw.indexOf('\n\n');
    final headerSection = headerBodySplit > 0
        ? raw.substring(0, headerBodySplit)
        : raw;
    final body = headerBodySplit > 0
        ? raw.substring(headerBodySplit + 2).trim()
        : '';

    // Extract individual headers
    final headers = _parseHeaders(headerSection);

    final fromHeader = headers['from'] ?? '';
    final senderEmail = _extractEmail(fromHeader);
    final senderName = _extractDisplayName(fromHeader);
    final replyTo = headers['reply-to'] != null
        ? _extractEmail(headers['reply-to']!)
        : null;
    final subject = headers['subject'] ?? '';

    // Extract URLs from body
    final urls = _extractUrls(body);

    // Extract all raw header names for anomaly detection
    final rawHeaders = headers.keys.toList();

    return ParsedEmail(
      senderEmail: senderEmail,
      senderDisplayName: senderName,
      replyToEmail: replyTo,
      subject: subject,
      body: body,
      embeddedUrls: urls,
      rawHeaders: rawHeaders,
      hasHeaders: true,
      fullText: raw,
    );
  }

  /// Parse body-only input
  ParsedEmail _parseBodyOnly(String body) {
    // Try to extract sender email from body text
    final emails = _emailPattern
        .allMatches(body)
        .map((m) => m.group(0)!)
        .toList();
    final urls = _extractUrls(body);

    // Attempt to find "From:" pattern even without formal headers
    String? inferredSender;
    final fromMatch = RegExp(
      r'from[:\s]+(\S+@\S+)',
      caseSensitive: false,
    ).firstMatch(body);
    if (fromMatch != null) {
      inferredSender = fromMatch.group(1);
    } else if (emails.isNotEmpty) {
      inferredSender = emails.first;
    }

    return ParsedEmail(
      senderEmail: inferredSender,
      senderDisplayName: null,
      replyToEmail: null,
      subject: null,
      body: body,
      embeddedUrls: urls,
      rawHeaders: [],
      hasHeaders: false,
      fullText: body,
    );
  }

  /// Parse header section into key-value map
  Map<String, String> _parseHeaders(String headerSection) {
    final headers = <String, String>{};
    String? currentKey;
    final buffer = StringBuffer();

    for (final line in headerSection.split('\n')) {
      if (line.startsWith(' ') || line.startsWith('\t')) {
        // Continuation of previous header
        buffer.write(' ${line.trim()}');
      } else {
        // Save previous header
        if (currentKey != null) {
          headers[currentKey] = buffer.toString().trim();
        }
        // Parse new header
        final colonIdx = line.indexOf(':');
        if (colonIdx > 0) {
          currentKey = line.substring(0, colonIdx).trim().toLowerCase();
          buffer
            ..clear()
            ..write(line.substring(colonIdx + 1).trim());
        }
      }
    }
    // Save last header
    if (currentKey != null) {
      headers[currentKey] = buffer.toString().trim();
    }

    return headers;
  }

  /// Extract email address from a header value like `"John Doe <john@example.com>"`
  String? _extractEmail(String headerValue) {
    final match = _emailPattern.firstMatch(headerValue);
    return match?.group(0);
  }

  /// Extract display name from `"John Doe <john@example.com>"`
  String? _extractDisplayName(String headerValue) {
    final angleBracket = headerValue.indexOf('<');
    if (angleBracket > 0) {
      final name = headerValue.substring(0, angleBracket).trim();
      // Remove surrounding quotes
      return name.replaceAll(RegExp(r'''['"]+'''), '').trim();
    }
    return null;
  }

  /// Extract all URLs from text (plain text + HTML href attributes)
  List<String> _extractUrls(String text) {
    final urls = <String>{};

    // 1. Plain text URLs (http:// or https://)
    for (final match in _urlPattern.allMatches(text)) {
      urls.add(match.group(0)!);
    }

    // 2. HTML href attributes (from "Show Original" raw email)
    final hrefPattern = RegExp(
      r'''href\s*=\s*["']([^"']+)["']''',
      caseSensitive: false,
    );
    for (final match in hrefPattern.allMatches(text)) {
      final href = match.group(1);
      if (href != null && href.startsWith('http')) {
        urls.add(href);
      }
    }

    // 3. URL-encoded href (=3D"..." in MIME-encoded emails)
    final encodedHrefPattern = RegExp(
      r'href=3D"([^"]+)"',
      caseSensitive: false,
    );
    for (final match in encodedHrefPattern.allMatches(text)) {
      final href = match.group(1);
      if (href != null && href.startsWith('http')) {
        urls.add(href);
      }
    }

    return urls.toList();
  }
}

/// Structured email data extracted by the parser
class ParsedEmail {
  final String? senderEmail;
  final String? senderDisplayName;
  final String? replyToEmail;
  final String? subject;
  final String body;
  final List<String> embeddedUrls;
  final List<String> rawHeaders;
  final bool hasHeaders;
  final String fullText;

  const ParsedEmail({
    required this.senderEmail,
    required this.senderDisplayName,
    required this.replyToEmail,
    required this.subject,
    required this.body,
    required this.embeddedUrls,
    required this.rawHeaders,
    required this.hasHeaders,
    required this.fullText,
  });

  factory ParsedEmail.empty() => const ParsedEmail(
    senderEmail: null,
    senderDisplayName: null,
    replyToEmail: null,
    subject: null,
    body: '',
    embeddedUrls: [],
    rawHeaders: [],
    hasHeaders: false,
    fullText: '',
  );

  /// The sender's domain (e.g. "gmail.com")
  String? get senderDomain {
    if (senderEmail == null) return null;
    final parts = senderEmail!.split('@');
    return parts.length == 2 ? parts[1].toLowerCase() : null;
  }

  /// Whether reply-to differs from sender
  bool get hasReplyToMismatch =>
      replyToEmail != null &&
      senderEmail != null &&
      replyToEmail!.toLowerCase() != senderEmail!.toLowerCase();

  @override
  String toString() =>
      'ParsedEmail(from: $senderEmail, subject: $subject, urls: ${embeddedUrls.length})';
}
