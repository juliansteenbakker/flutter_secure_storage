#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint flutter_secure_storage_macos.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'flutter_secure_storage_macos'
  s.version          = '6.1.1'
  s.summary          = 'Flutter Secure Storage'
  s.description      = <<-DESC
Flutter Secure Storage Plugin for MacOs
                       DESC
  s.homepage         = 'https://github.com/mogol/flutter_secure_storage'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'German Saprykin' => 'saprykin.h@gmail.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'FlutterMacOS'

  s.platform = :osx, '10.14'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
  s.resource_bundles = {'flutter_secure_storage_macos' => ['Resources/PrivacyInfo.xcprivacy']}
end
