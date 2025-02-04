import 'dart:math' show Random;

import 'package:flutter/foundation.dart' show defaultTargetPlatform, kIsWeb;
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

void main() {
  runApp(const MaterialApp(home: HomePage()));
}

enum _Actions { deleteAll, isProtectedDataAvailable }

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

  void _initializeFlutterSecureStorage(String accountName) {
    _storage = FlutterSecureStorage(
      iOptions: IOSOptions(accountName: accountName),
      mOptions: MacOsOptions(accountName: accountName),
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
    final all = await _storage.readAll();
    setState(() {
      _items
        ..clear()
        ..addAll(all.entries.map((e) => _SecItem(e.key, e.value)))
        ..sort(
          (a, b) =>
              (int.tryParse(a.key) ?? 10).compareTo(int.tryParse(b.key) ?? 11),
        );
    });
  }

  Future<void> _deleteAll() async {
    await _storage.deleteAll();
    await _readAll();
  }

  Future<void> _isProtectedDataAvailable() async {
    final scaffold = ScaffoldMessenger.of(context);
    final result = await _storage.isCupertinoProtectedDataAvailable();

    scaffold.showSnackBar(
      SnackBar(
        content: Text('Protected data available: $result'),
        backgroundColor: result != null && result ? Colors.green : Colors.red,
      ),
    );
  }

  Future<void> _addNewItem() async {
    await _storage.write(
      key: DateTime.timestamp().microsecondsSinceEpoch.toString(),
      value: _randomValue(),
    );
    await _readAll();
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
