// GENERATED CODE - DO NOT MODIFY BY HAND

// **************************************************************************
// StackedLocatorGenerator
// **************************************************************************

// ignore_for_file: public_member_api_docs, implementation_imports, depend_on_referenced_packages

import 'package:stacked_services/src/dialog/dialog_service.dart';
import 'package:stacked_services/src/navigation/navigation_service.dart';
import 'package:stacked_services/src/snackbar/snackbar_service.dart';
import 'package:stacked_shared/stacked_shared.dart';

import '../services/ai_service.dart';
import '../services/benchmark_service.dart';
import '../services/content_analysis_service.dart';
import '../services/device_id_service.dart';
import '../services/firestore_service.dart';
import '../services/host_analysis_service.dart';
import '../services/multi_modal_engine.dart';
import '../services/phishing_service.dart';
import '../services/sequential_analyzer.dart';
import '../services/ssl_analysis_service.dart';
import '../services/url_feature_extractor.dart';
import '../services/email_parser.dart';
import '../services/email_header_analyzer.dart';
import '../services/email_content_analyzer.dart';
import '../services/email_multi_modal_engine.dart';
import '../services/email_phishing_service.dart';

final locator = StackedLocator.instance;

Future<void> setupLocator({
  String? environment,
  EnvironmentFilter? environmentFilter,
}) async {
  // Register environments
  locator.registerEnvironment(
    environment: environment,
    environmentFilter: environmentFilter,
  );

  // Register dependencies — Multi-modal detection services
  locator.registerLazySingleton(() => UrlFeatureExtractor());
  locator.registerLazySingleton(() => SequentialAnalyzer());
  locator.registerLazySingleton(() => HostAnalysisService());
  locator.registerLazySingleton(() => SslAnalysisService());
  locator.registerLazySingleton(() => ContentAnalysisService());
  locator.registerLazySingleton(() => MultiModalEngine());
  locator.registerLazySingleton(() => BenchmarkService());

  // Register dependencies — Email analysis services
  locator.registerLazySingleton(() => EmailParser());
  locator.registerLazySingleton(() => EmailHeaderAnalyzer());
  locator.registerLazySingleton(() => EmailContentAnalyzer());
  locator.registerLazySingleton(() => EmailMultiModalEngine());
  locator.registerLazySingleton(() => EmailPhishingService());

  // Register dependencies — Core services
  locator.registerLazySingleton(() => AiService());
  locator.registerLazySingleton(() => PhishingService());
  locator.registerLazySingleton(() => FirestoreService());
  locator.registerLazySingleton(() => DeviceIdService());

  // Register dependencies — Stacked services
  locator.registerLazySingleton(() => NavigationService());
  locator.registerLazySingleton(() => DialogService());
  locator.registerLazySingleton(() => SnackbarService());
}
