part of '../flutter_secure_storage_platform_interface.dart';

abstract class Options {
  const Options();

  Map<String, String> get params => toMap();

  @protected
  Map<String, String> toMap();
}
