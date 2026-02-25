import 'package:flutter/material.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:trustprobe_ai/app/app.locator.dart';
import 'package:trustprobe_ai/app/app.router.dart';
import 'package:trustprobe_ai/services/device_id_service.dart';
import 'package:stacked_services/stacked_services.dart';
import 'firebase_options.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize Firebase with auto-generated config
  await Firebase.initializeApp(options: DefaultFirebaseOptions.currentPlatform);

  // Setup Stacked locator (dependency injection)
  setupLocator();

  // Initialize device ID for anonymous scan tracking
  await locator<DeviceIdService>().initialize();

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'TrustProbe AI',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        brightness: Brightness.dark,
        primaryColor: Color(0xFF00d2ff),
        scaffoldBackgroundColor: Color(0xFF1a1a2e),
        useMaterial3: true,
      ),
      navigatorKey: StackedService.navigatorKey,
      onGenerateRoute: StackedRouter().onGenerateRoute,
    );
  }
}
