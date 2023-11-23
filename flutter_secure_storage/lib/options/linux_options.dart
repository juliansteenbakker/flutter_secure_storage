part of '../flutter_secure_storage.dart';

/// Specific options for Linux platform.
/// Currently there are no specific linux options available.
class LinuxOptions extends Options {
  const LinuxOptions();

  static const LinuxOptions defaultOptions = LinuxOptions();

  @override
  Map<String, String> toMap() {
    return <String, String>{};
  }
}
