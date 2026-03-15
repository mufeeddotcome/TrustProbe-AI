import 'package:flutter_test/flutter_test.dart';
import 'package:trustprobe_ai/app/app.locator.dart';
import 'package:trustprobe_ai/services/firestore_service.dart';
import 'package:trustprobe_ai/services/device_id_service.dart';
import 'package:trustprobe_ai/services/phishing_service.dart';
import 'package:trustprobe_ai/main.dart';
import 'mocks.dart';

void main() {
  setUpAll(() async {
    // Setup the locator for testing
    await setupLocator();
    
    // Replace problematic services with mocks
    if (locator.isRegistered<FirestoreService>()) {
      locator.unregister<FirestoreService>();
    }
    locator.registerSingleton<FirestoreService>(MockFirestoreService());

    if (locator.isRegistered<DeviceIdService>()) {
      locator.unregister<DeviceIdService>();
    }
    locator.registerSingleton<DeviceIdService>(MockDeviceIdService());

    if (locator.isRegistered<PhishingService>()) {
      locator.unregister<PhishingService>();
    }
    locator.registerSingleton<PhishingService>(MockPhishingService());
  });

  testWidgets('App basic smoke test', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    // We use a shorter pump or skip complex initialization if possible.
    await tester.pumpWidget(const MyApp());

    // Verify that the app builds correctly
    expect(find.byType(MyApp), findsOneWidget);
  });
}
