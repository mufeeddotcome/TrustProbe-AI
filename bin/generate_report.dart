import 'dart:convert';
import 'dart:io';

import 'package:inline_logger/inline_logger.dart';

void main() async {
  final resultsFile = File('test_results.json');
  if (!await resultsFile.exists()) {
    Logger.info(
      'Error: test_results.json not found. Please run "flutter test --machine > test_results.json" first.',
    );
    exit(1);
  }

  final lines = await resultsFile.readAsLines();
  final List<dynamic> events = [];

  for (var line in lines) {
    line = line.trim();
    if (line.isEmpty) continue;
    try {
      final decoded = jsonDecode(line);
      if (decoded is Map<String, dynamic>) {
        events.add(decoded);
      } else if (decoded is List && decoded.isNotEmpty) {
        // Some flutter test output lines are lists of events
        for (var item in decoded) {
          if (item is Map<String, dynamic>) {
            events.add(item);
          }
        }
      }
    } catch (_) {
      // Skip invalid JSON lines
    }
  }

  final summary = _processEvents(events);
  final html = _generateHtml(summary);

  await File('test_report.html').writeAsString(html);
  Logger.info('Test report generated: test_report.html');
}

class TestSummary {
  int totalCount = 0;
  int successCount = 0;
  int failureCount = 0;
  int skipCount = 0;
  Duration totalDuration = Duration.zero;
  List<TestResult> tests = [];
}

class TestResult {
  final String name;
  final String status;
  final Duration duration;
  final String? error;
  final String? stackTrace;

  TestResult({
    required this.name,
    required this.status,
    required this.duration,
    this.error,
    this.stackTrace,
  });
}

TestSummary _processEvents(List<dynamic> events) {
  final summary = TestSummary();
  final Map<int, Map<String, dynamic>> testDetails = {};
  DateTime? startTime;

  for (var event in events) {
    final type = event['type'];

    if (type == 'start' && startTime == null) {
      startTime = DateTime.fromMillisecondsSinceEpoch(event['time'] ?? 0);
    }

    if (type == 'testStart') {
      final test = event['test'];
      testDetails[test['id']] = {
        'name': test['name'],
        'startTime': event['time'],
      };
    }

    if (type == 'error') {
      final testId = event['testID'];
      if (testDetails.containsKey(testId)) {
        testDetails[testId]!['error'] = event['error'];
        testDetails[testId]!['stackTrace'] = event['stackTrace'];
      }
    }

    if (type == 'testDone') {
      final testId = event['testID'];
      final result = event['result'];
      final testInfo = testDetails[testId];

      if (testInfo != null) {
        final duration = Duration(
          milliseconds: event['time'] - testInfo['startTime'],
        );
        final testName = testInfo['name'] as String;

        // Skip group/loading events that aren't actual tests if name is empty or similar
        if (testName.isEmpty || testName.startsWith('loading ')) continue;

        summary.totalCount++;
        if (result == 'success') {
          summary.successCount++;
        } else if (result == 'failure') {
          summary.failureCount++;
        } else if (result == 'skipped') {
          summary.skipCount++;
        }

        summary.tests.add(
          TestResult(
            name: testName,
            status: result,
            duration: duration,
            error: testInfo['error'],
            stackTrace: testInfo['stackTrace'],
          ),
        );

        summary.totalDuration += duration;
      }
    }
  }

  return summary;
}

String _generateHtml(TestSummary summary) {
  final now = DateTime.now();
  final timestamp =
      '${now.year}-${now.month.toString().padLeft(2, '0')}-${now.day.toString().padLeft(2, '0')} '
      '${now.hour.toString().padLeft(2, '0')}:${now.minute.toString().padLeft(2, '0')}';

  final rows = summary.tests
      .map((t) {
        final statusClass = t.status == 'success'
            ? 'status-pass'
            : (t.status == 'failure' ? 'status-fail' : 'status-skip');
        final statusText = t.status.toUpperCase();
        final duration = '${t.duration.inMilliseconds}ms';

        String errorSection = '';
        if (t.error != null) {
          errorSection =
              '''
        <div class="error-msg">
          <strong>Error:</strong> ${t.error}<br>
          <pre>${t.stackTrace ?? ''}</pre>
        </div>
      ''';
        }

        return '''
      <tr>
        <td>${t.name}</td>
        <td><span class="status-badge $statusClass">$statusText</span></td>
        <td>$duration</td>
      </tr>
      ${t.status == 'failure' ? '<tr><td colspan="3">$errorSection</td></tr>' : ''}
    ''';
      })
      .join('\n');

  final passRate = summary.totalCount > 0
      ? (summary.successCount / summary.totalCount * 100).toStringAsFixed(1)
      : '0';

  return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustProbe AI - Automation Test Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #2563eb;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --bg: #f8fafc;
            --card: #ffffff;
            --text: #1e293b;
            --text-muted: #64748b;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        header {
            margin-bottom: 40px;
            text-align: center;
        }
        h1 {
            font-weight: 700;
            font-size: 2.5rem;
            margin-bottom: 10px;
            color: var(--text);
        }
        .meta {
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .stat-card {
            background: var(--card);
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            display: block;
        }
        .stat-label {
            color: var(--text-muted);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .results-card {
            background: var(--card);
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            overflow: hidden;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #f1f5f9;
            text-align: left;
            padding: 16px;
            font-weight: 600;
            border-bottom: 1px solid #e2e8f0;
        }
        td {
            padding: 16px;
            border-bottom: 1px solid #f1f5f9;
        }
        .status-badge {
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .status-pass { background: #d1fae5; color: #065f46; }
        .status-fail { background: #fee2e2; color: #991b1b; }
        .status-skip { background: #fef3c7; color: #92400e; }
        .error-msg {
            background: #fffafa;
            border-left: 4px solid var(--danger);
            padding: 12px;
            margin: 10px 0;
            font-size: 0.875rem;
        }
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: monospace;
            background: #f8fafc;
            padding: 10px;
            border-radius: 4px;
            margin-top: 5px;
        }
        footer {
            margin-top: 60px;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.875rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>TrustProbe AI</h1>
            <div class="meta">Automated Test Execution Report • Generated on $timestamp</div>
        </header>

        <div class="dashboard">
            <div class="stat-card">
                <span class="stat-value">${summary.totalCount}</span>
                <span class="stat-label">Total Tests</span>
            </div>
            <div class="stat-card">
                <span class="stat-value" style="color: var(--success)">${summary.successCount}</span>
                <span class="stat-label">Passed</span>
            </div>
            <div class="stat-card">
                <span class="stat-value" style="color: var(--danger)">${summary.failureCount}</span>
                <span class="stat-label">Failed</span>
            </div>
            <div class="stat-card">
                <span class="stat-value" style="color: var(--primary)">$passRate%</span>
                <span class="stat-label">Pass Rate</span>
            </div>
        </div>

        <div class="results-card">
            <table>
                <thead>
                    <tr>
                        <th style="width: 70%">Test Case</th>
                        <th>Status</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody>
                    $rows
                </tbody>
            </table>
        </div>

        <footer>
            &copy; 2024 TrustProbe AI Academic Project • Security Testing Documentation
        </footer>
    </div>
</body>
</html>
''';
}
