import 'dart:math' show Random;

import 'package:flutter/foundation.dart' show defaultTargetPlatform, kIsWeb;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

void main() {
  runApp(const MaterialApp(home: HomePage()));
}

enum _Actions { deleteAll, isProtectedDataAvailable, readALl }

enum _ItemActions { delete, edit, containsKey, read }

/// Homepage of the example app of flutter_secure_storage
class HomePage extends StatefulWidget {
  /// Creates an instance of `HomePage`.
  const HomePage({super.key});

  @override
  HomePageState createState() => HomePageState();
}

/// The `HomePageState` class represents the mutable state for the `HomePage`
/// widget. It manages the state and behavior of the user interface.
class HomePageState extends State<HomePage> {
  late FlutterSecureStorage _storage;

  final TextEditingController _accountNameController =
      TextEditingController(text: AppleOptions.defaultAccountName);

  final List<_SecItem> _items = [];
  String _errorMessage = '';

  void _initializeFlutterSecureStorage(String accountName) {
    _storage = FlutterSecureStorage(
      aOptions: const AndroidOptions(
        biometricPromptTitle: 'Flutter Secure Storage Example',
        biometricPromptSubtitle: 'Please unlock to access data.',
      ),
      iOptions: IOSOptions(
        accountName: accountName,
        synchronizable: true,
        // accessControlFlags: [ // Enable for one or more access control features
        //   AccessControlFlag.biometryCurrentSet,
        //   AccessControlFlag.devicePasscode,
        //   AccessControlFlag.and,
        // ],
      ),
      mOptions: MacOsOptions(
        accountName: accountName,
        synchronizable: true,
        // accessControlFlags: [ // Enable for one or more access control features
        //   AccessControlFlag.biometryCurrentSet,
        //   AccessControlFlag.devicePasscode,
        //   AccessControlFlag.and,
        // ],
      ),
    );
  }

  void _updateAccountName() {
    if (_accountNameController.text.isEmpty) return;

    _initializeFlutterSecureStorage(_accountNameController.text);
    _readAll();
  }

  @override
  void initState() {
    super.initState();
    _initializeFlutterSecureStorage(AppleOptions.defaultAccountName);
    _accountNameController.addListener(_updateAccountName);
    _readAll();
  }

  @override
  void dispose() {
    _accountNameController
      ..removeListener(_updateAccountName)
      ..dispose();

    super.dispose();
  }

  Future<void> _readAll() async {
    try {
      final all = await _storage.readAll();
      setState(() {
        _items
          ..clear()
          ..addAll(all.entries.map((e) => _SecItem(e.key, e.value)))
          ..sort(
            (a, b) => (int.tryParse(a.key) ?? 10)
                .compareTo(int.tryParse(b.key) ?? 11),
          );
      });
    } on PlatformException catch (e) {
      _handleInitializationError(e);
    }
  }

  Future<void> _deleteAll() async {
    try {
      await _storage.deleteAll();
      await _readAll();
    } on PlatformException catch (e) {
      _handleInitializationError(e);
    }
  }

  Future<void> _isProtectedDataAvailable() async {
    final scaffold = ScaffoldMessenger.of(context);
    try {
      final result = await _storage.isCupertinoProtectedDataAvailable();

      scaffold.showSnackBar(
        SnackBar(
          content: Text('Protected data available: $result'),
          backgroundColor: result != null && result ? Colors.green : Colors.red,
        ),
      );
    } on PlatformException catch (e) {
      _handleInitializationError(e);
    }
  }

  Future<void> _addNewItem() async {
    try {
      await _storage.write(
        key: DateTime.timestamp().microsecondsSinceEpoch.toString(),
        value: _randomValue(),
      );
      await _readAll();
    } on PlatformException catch (e) {
      _handleInitializationError(e);
    }
  }

  void _handleInitializationError(PlatformException e) {
    String userMessage;
    final technicalDetails = e.message ?? 'Unknown error';

    // Check for BIOMETRIC_UNAVAILABLE error
    if (technicalDetails.contains('BIOMETRIC_UNAVAILABLE')) {
      // Parse specific biometric error
      if (technicalDetails.contains('No biometric hardware')) {
        userMessage = 'Your device does not have biometric hardware '
            '(fingerprint or face scanner).';
      } else if (technicalDetails.contains('No fingerprint or face enrolled')) {
        userMessage = 'No biometric enrolled. Please add a fingerprint or '
            'face in your device Settings.';
      } else if (technicalDetails.contains('no PIN, pattern, password')) {
        userMessage = 'No device security set up. Please set a PIN, '
            'pattern, or password in Settings → Security.';
      } else if (technicalDetails.contains('Android 9')) {
        userMessage = 'Biometric authentication requires Android 9 or '
            'higher. Your device is not supported.';
      } else if (technicalDetails.contains('temporarily unavailable')) {
        userMessage =
            'Biometric hardware is temporarily unavailable. Please try again.';
      } else {
        userMessage =
            'Biometric authentication is not available on this device.';
      }

      setState(() {
        _errorMessage = userMessage;
      });
      _showErrorDialog('Biometric Setup Required', userMessage);
      return;
    }

    switch (e.code) {
      case 'INIT_FAILED':
        _showErrorDialog(
          'Initialization Failed',
          e.message ?? 'An unknown error occurred during initialization.',
        );
      case 'AUTHENTICATION_FAILED':
        _showErrorDialog(
          'Authentication Failed',
          'Biometric authentication failed. Please try again.',
        );
      case 'InvalidArgument':
        _showErrorDialog(
          'Argument Error',
          'A with an argument occured. ${e.message}',
        );
      default:
        _showErrorDialog('Error', 'An unexpected error occurred: ${e.message}');
    }
  }

  void _showErrorDialog(String title, String message) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      showDialog<void>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text(title),
          content: Text(message),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('OK'),
            ),
          ],
        ),
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Plugin example app'),
        actions: <Widget>[
          IconButton(
            key: const Key('add_random'),
            onPressed: _addNewItem,
            icon: const Icon(Icons.add),
          ),
          PopupMenuButton<_Actions>(
            key: const Key('popup_menu'),
            onSelected: (action) {
              switch (action) {
                case _Actions.deleteAll:
                  _deleteAll();
                case _Actions.readALl:
                  _readAll();
                case _Actions.isProtectedDataAvailable:
                  _isProtectedDataAvailable();
              }
            },
            itemBuilder: (BuildContext context) => <PopupMenuEntry<_Actions>>[
              const PopupMenuItem(
                key: Key('delete_all'),
                value: _Actions.deleteAll,
                child: Text('Delete all'),
              ),
              const PopupMenuItem(
                key: Key('read_all'),
                value: _Actions.readALl,
                child: Text('Read all'),
              ),
              const PopupMenuItem(
                key: Key('is_protected_data_available'),
                value: _Actions.isProtectedDataAvailable,
                child: Text('IsProtectedDataAvailable'),
              ),
            ],
          ),
        ],
      ),
      body: Column(
        children: [
          if (!kIsWeb &&
              (defaultTargetPlatform == TargetPlatform.iOS ||
                  defaultTargetPlatform == TargetPlatform.macOS))
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: TextFormField(
                controller: _accountNameController,
                decoration: const InputDecoration(labelText: 'kSecAttrService'),
              ),
            ),
          if (_errorMessage.isNotEmpty &&
              !kIsWeb &&
              defaultTargetPlatform == TargetPlatform.android)
            Container(
              margin: const EdgeInsets.all(16),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.red.shade50,
                border: Border.all(color: Colors.red.shade300),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Row(
                    children: [
                      Icon(Icons.error_outline, color: Colors.red),
                      SizedBox(width: 8),
                      Text(
                        'Error',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          color: Colors.red,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(
                    _errorMessage,
                    style: TextStyle(color: Colors.red.shade900),
                  ),
                ],
              ),
            ),
          Expanded(
            child: ListView.builder(
              itemCount: _items.length,
              itemBuilder: (BuildContext context, int index) => ListTile(
                trailing: PopupMenuButton(
                  key: Key('popup_row_$index'),
                  onSelected: (_ItemActions action) =>
                      _performAction(action, _items[index], context),
                  itemBuilder: (BuildContext context) =>
                      <PopupMenuEntry<_ItemActions>>[
                    PopupMenuItem(
                      value: _ItemActions.delete,
                      child: Text(
                        'Delete',
                        key: Key('delete_row_$index'),
                      ),
                    ),
                    PopupMenuItem(
                      value: _ItemActions.edit,
                      child: Text(
                        'Edit',
                        key: Key('edit_row_$index'),
                      ),
                    ),
                    PopupMenuItem(
                      value: _ItemActions.containsKey,
                      child: Text(
                        'Contains Key',
                        key: Key('contains_row_$index'),
                      ),
                    ),
                    PopupMenuItem(
                      value: _ItemActions.read,
                      child: Text(
                        'Read',
                        key: Key('read_row_$index'),
                      ),
                    ),
                  ],
                ),
                leading: const Column(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [Text('Value'), Text('Key')],
                ),
                title: Text(
                  _items[index].value,
                  key: Key('value_row_$index'),
                ),
                subtitle: Text(
                  _items[index].key,
                  key: Key('key_row_$index'),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _performAction(
    _ItemActions action,
    _SecItem item,
    BuildContext context,
  ) async {
    try {
      switch (action) {
        case _ItemActions.delete:
          await _storage.delete(
            key: item.key,
          );
          await _readAll();
        case _ItemActions.edit:
          if (!context.mounted) return;
          final result = await showDialog<String>(
            context: context,
            builder: (_) => _EditItemWidget(item.value),
          );
          if (result != null) {
            await _storage.write(
              key: item.key,
              value: result,
            );
            await _readAll();
          }
        case _ItemActions.containsKey:
          final key = await _displayTextInputDialog(context, item.key);
          final result = await _storage.containsKey(key: key);
          if (!context.mounted) return;
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Contains Key: $result, key checked: $key'),
              backgroundColor: result ? Colors.green : Colors.red,
            ),
          );
        case _ItemActions.read:
          final key = await _displayTextInputDialog(context, item.key);
          final result = await _storage.read(key: key);
          if (!context.mounted) return;
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('value: $result'),
            ),
          );
      }
    } on PlatformException catch (e) {
      _handleInitializationError(e);
    }
  }

  Future<String> _displayTextInputDialog(
    BuildContext context,
    String key,
  ) async {
    final controller = TextEditingController(text: key);
    await showDialog<dynamic>(
      context: context,
      builder: (BuildContext context) => AlertDialog(
        title: const Text('Check if key exists'),
        actions: [
          TextButton(
            onPressed: Navigator.of(context).pop,
            child: const Text('OK'),
          ),
        ],
        content: TextField(
          controller: controller,
          key: const Key('key_field'),
        ),
      ),
    );
    return controller.text;
  }

  String _randomValue() {
    final rand = Random();
    final codeUnits =
        List<int>.generate(20, (_) => rand.nextInt(26) + 65, growable: false);

    return String.fromCharCodes(codeUnits);
  }
}

class _EditItemWidget extends StatelessWidget {
  _EditItemWidget(String text)
      : _controller = TextEditingController(text: text);

  final TextEditingController _controller;

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Edit item'),
      content: TextField(
        key: const Key('value_field'),
        controller: _controller,
        autofocus: true,
      ),
      actions: <Widget>[
        TextButton(
          key: const Key('cancel'),
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        TextButton(
          key: const Key('save'),
          onPressed: () => Navigator.of(context).pop(_controller.text),
          child: const Text('Save'),
        ),
      ],
    );
  }
}

class _SecItem {
  const _SecItem(this.key, this.value);

  final String key;
  final String value;
}
