#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#
Pod::Spec.new do |s|
  s.name             = 'flutter_secure_storage'
  s.version          = '6.0.0'
  s.summary          = 'A Flutter plugin to store data in secure storage.'
  s.description      = <<-DESC
A Flutter plugin to store data in secure storage.
                       DESC
  s.homepage         = 'http://example.com'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'German Saprykin' => 'saprykin.h@gmail.com' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'
  s.dependency 'Flutter'
  s.platform = :ios, '9.0'
  s.ios.deployment_target = '9.0'

    # Flutter.framework does not contain a i386 slice.
    s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
    s.swift_version = '5.0'
    s.resource_bundles = {'flutter_secure_storage' => ['Resources/PrivacyInfo.xcprivacy']}
end

