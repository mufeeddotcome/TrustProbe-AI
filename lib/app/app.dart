import 'package:stacked/stacked_annotations.dart';
import 'package:stacked_services/stacked_services.dart';
import 'package:trustprobe_ai/ui/views/home/home_view.dart';
import 'package:trustprobe_ai/services/phishing_service.dart';
import 'package:trustprobe_ai/services/firestore_service.dart';
import 'package:trustprobe_ai/services/ai_service.dart';
import 'package:trustprobe_ai/services/url_feature_extractor.dart';
import 'package:trustprobe_ai/services/sequential_analyzer.dart';
import 'package:trustprobe_ai/services/host_analysis_service.dart';
import 'package:trustprobe_ai/services/ssl_analysis_service.dart';
import 'package:trustprobe_ai/services/content_analysis_service.dart';
import 'package:trustprobe_ai/services/multi_modal_engine.dart';
import 'package:trustprobe_ai/services/benchmark_service.dart';
import 'package:trustprobe_ai/services/email_parser.dart';
import 'package:trustprobe_ai/services/email_header_analyzer.dart';
import 'package:trustprobe_ai/services/email_content_analyzer.dart';
import 'package:trustprobe_ai/services/email_multi_modal_engine.dart';
import 'package:trustprobe_ai/services/email_phishing_service.dart';

/// Stacked App Configuration
///
/// This file configures the app's routes and dependency injection.
/// After modifying this file, run:
/// flutter pub run build_runner build --delete-conflicting-outputs
@StackedApp(
  routes: [MaterialRoute(page: HomeView, initial: true)],
  dependencies: [
    // Multi-modal detection services
    LazySingleton(classType: UrlFeatureExtractor),
    LazySingleton(classType: SequentialAnalyzer),
    LazySingleton(classType: HostAnalysisService),
    LazySingleton(classType: SslAnalysisService),
    LazySingleton(classType: ContentAnalysisService),
    LazySingleton(classType: MultiModalEngine),
    LazySingleton(classType: BenchmarkService),
    // Email analysis services
    LazySingleton(classType: EmailParser),
    LazySingleton(classType: EmailHeaderAnalyzer),
    LazySingleton(classType: EmailContentAnalyzer),
    LazySingleton(classType: EmailMultiModalEngine),
    LazySingleton(classType: EmailPhishingService),
    // Core services
    LazySingleton(classType: AiService),
    LazySingleton(classType: PhishingService),
    LazySingleton(classType: FirestoreService),
    // Stacked services
    LazySingleton(classType: NavigationService),
    LazySingleton(classType: DialogService),
    LazySingleton(classType: SnackbarService),
  ],
)
class App {}
