#import "FlutterSecureStoragePlugin.h"
#if __has_include(<flutter_secure_storage/flutter_secure_storage-Swift.h>)
#import <flutter_secure_storage/flutter_secure_storage-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "flutter_secure_storage-Swift.h"
#endif

@implementation FlutterSecureStoragePlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftFlutterSecureStoragePlugin registerWithRegistrar:registrar];
}
@end


//#import "FlutterSecureStoragePlugin.h"
//
//static NSString *const CHANNEL_NAME = @"plugins.it_nomads.com/flutter_secure_storage";
//
//static NSString *const InvalidParameters = @"Invalid parameter's type";
//
//@interface FlutterSecureStoragePlugin()
//
//@property (strong, nonatomic) NSDictionary *query;
//
//@end
//
//@implementation FlutterSecureStoragePlugin
//
//- (instancetype)init {
//    self = [super init];
//    if (self){
//        self.query = @{
//                       (__bridge id)kSecClass :(__bridge id)kSecClassGenericPassword,
//                       };
//    }
//    return self;
//}
//
//+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
//    FlutterMethodChannel* channel = [FlutterMethodChannel
//                                     methodChannelWithName:CHANNEL_NAME
//                                     binaryMessenger:[registrar messenger]];
//    FlutterSecureStoragePlugin* instance = [[FlutterSecureStoragePlugin alloc] init];
//    [registrar addMethodCallDelegate:instance channel:channel];
//}
//
//- (void)handleMethodCall:(FlutterMethodCall*)call result:(FlutterResult)result {
//    NSDictionary *arguments = [call arguments];
//    NSDictionary *options = [arguments[@"options"] isKindOfClass:[NSDictionary class]] ? arguments[@"options"] : nil;
//    NSString *accountName = options[@"accountName"];
//    NSString *groupId = options[@"groupId"];
//    NSString *synchronizable = options[@"synchronizable"];
//
//    if ([@"read" isEqualToString:call.method]) {
//        NSString *key = arguments[@"key"];
//        NSString *value = [self read:key forGroup:groupId forAccountName:accountName forSynchronizable:synchronizable];
//
//        result(value);
//    } else if ([@"write" isEqualToString:call.method]) {
//        NSString *key = arguments[@"key"];
//        NSString *value = arguments[@"value"];
//        NSString *accessibility = options[@"accessibility"];
//
//        if (![value isKindOfClass:[NSString class]]){
//            result(InvalidParameters);
//            return;
//        }
//
//        [self write:value forKey:key forGroup:groupId accessibilityAttr:accessibility forAccountName:accountName forSynchronizable:synchronizable];
//
//        result(nil);
//    } else if ([@"delete" isEqualToString:call.method]) {
//        NSString *key = arguments[@"key"];
//
//        [self delete:key forGroup:groupId forAccountName:accountName forSynchronizable:synchronizable];
//
//        result(nil);
//    } else if ([@"deleteAll" isEqualToString:call.method]) {
//        [self deleteAll: groupId forAccountName:accountName forSynchronizable:synchronizable];
//
//        result(nil);
//    } else if ([@"readAll" isEqualToString:call.method]) {
//        NSDictionary *value = [self readAll: groupId forAccountName:accountName forSynchronizable:synchronizable];
//
//        result(value);
//    } else if ([@"containsKey" isEqualToString:call.method]) {
//        NSString *key = arguments[@"key"];
//        NSNumber *containsKey = [self containsKey:key forGroup:groupId forAccountName:accountName forSynchronizable:synchronizable];
//
//        result(containsKey);
//    } else {
//        result(FlutterMethodNotImplemented);
//    }
//}
//
//- (void)write:(NSString *)value forKey:(NSString *)key forGroup:(NSString *)groupId accessibilityAttr:(NSString *)accessibility forAccountName:(NSString *)accountName forSynchronizable:(NSString *)synchronizable {
//    NSMutableDictionary *search = [self.query mutableCopy];
//
//    if(groupId != nil) {
//        search[(__bridge id)kSecAttrAccessGroup] = groupId;
//    }
//
//    if(accountName != nil) {
//        search[(__bridge id)kSecAttrService] = accountName;
//    }
//
//    search[(__bridge id)kSecAttrAccount] = key;
//    search[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
//
//    CFBooleanRef attrSynchronizable = kCFBooleanFalse;
//    if ([synchronizable isEqualToString:@"true"]) {
//        attrSynchronizable = kCFBooleanTrue;
//    } else {
//        attrSynchronizable = kCFBooleanFalse;
//    }
//    search[(__bridge id)kSecAttrSynchronizable] = (__bridge id) attrSynchronizable;
//
//    // The default setting is kSecAttrAccessibleWhenUnlocked
//    CFStringRef attrAccessible = kSecAttrAccessibleWhenUnlocked;
//    if (accessibility != nil) {
//        if ([accessibility isEqualToString:@"passcode"]) {
//            attrAccessible = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly;
//        } else if ([accessibility isEqualToString:@"unlocked"]) {
//            attrAccessible = kSecAttrAccessibleWhenUnlocked;
//        } else if ([accessibility isEqualToString:@"unlocked_this_device"]) {
//            attrAccessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
//        } else if ([accessibility isEqualToString:@"first_unlock"]) {
//            attrAccessible = kSecAttrAccessibleAfterFirstUnlock;
//        } else if ([accessibility isEqualToString:@"first_unlock_this_device"]) {
//            attrAccessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
//        }
//    }
//
//    OSStatus status;
//    status = SecItemCopyMatching((__bridge CFDictionaryRef)search, NULL);
//    if (status == noErr){
//        search[(__bridge id)kSecMatchLimit] = nil;
//
//        NSDictionary *update = @{
//            (__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding],
//            (__bridge id)kSecAttrAccessible: (__bridge id) attrAccessible,
//            (__bridge id)kSecAttrSynchronizable: (__bridge id) attrSynchronizable,
//        };
//
//        status = SecItemUpdate((__bridge CFDictionaryRef)search, (__bridge CFDictionaryRef)update);
//        if (status != noErr){
//            NSLog(@"SecItemUpdate status = %d", (int) status);
//        }
//    }else{
//        search[(__bridge id)kSecValueData] = [value dataUsingEncoding:NSUTF8StringEncoding];
//        search[(__bridge id)kSecMatchLimit] = nil;
//        search[(__bridge id)kSecAttrAccessible] = (__bridge id) attrAccessible;
//
//        status = SecItemAdd((__bridge CFDictionaryRef)search, NULL);
//        if (status != noErr){
//            NSLog(@"SecItemAdd status = %d", (int) status);
//        }
//    }
//}
//
//- (NSString *)read:(NSString *)key forGroup:(NSString *)groupId forAccountName:(NSString *)accountName forSynchronizable:(NSString *)synchronizable {
//    NSMutableDictionary *search = [self.query mutableCopy];
//    if(groupId != nil) {
//     search[(__bridge id)kSecAttrAccessGroup] = groupId;
//    }
//    if(accountName != nil) {
//        search[(__bridge id)kSecAttrService] = accountName;
//    }
//    search[(__bridge id)kSecAttrAccount] = key;
//    search[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
//
//    if ([synchronizable isEqualToString:@"true"]) {
//        search[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kCFBooleanTrue;
//    } else {
//        search[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kCFBooleanFalse;
//    }
//
//    CFDataRef resultData = NULL;
//
//    OSStatus status;
//    status = SecItemCopyMatching((__bridge CFDictionaryRef)search, (CFTypeRef*)&resultData);
//    NSString *value;
//    if (status == noErr){
//        NSData *data = (__bridge NSData*)resultData;
//        value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
//        CFRelease(resultData);
//    }
//    return value;
//}
//
//- (void)delete:(NSString *)key forGroup:(NSString *)groupId forAccountName:(NSString *)accountName forSynchronizable:(NSString *)synchronizable {
//    NSMutableDictionary *search = [self.query mutableCopy];
//    if(groupId != nil) {
//        search[(__bridge id)kSecAttrAccessGroup] = groupId;
//    }
//    if(accountName != nil) {
//        search[(__bridge id)kSecAttrService] = accountName;
//    }
//    search[(__bridge id)kSecAttrAccount] = key;
//    search[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
//
//    if ([synchronizable isEqualToString:@"true"]) {
//        search[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kCFBooleanTrue;
//    } else {
//        search[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kCFBooleanFalse;
//    }
//
//    OSStatus status;
//    status = SecItemDelete((__bridge CFDictionaryRef)search);
//    if (status != noErr){
//        NSLog(@"SecItemDelete status = %d", (int) status);
//    }
//}
//
//- (void)deleteAll:(NSString *)groupId forAccountName:(NSString *)accountName forSynchronizable:(NSString *)synchronizable {
//    NSMutableDictionary *search = [self.query mutableCopy];
//    if(groupId != nil) {
//        search[(__bridge id)kSecAttrAccessGroup] = groupId;
//    }
//    if(accountName != nil) {
//        search[(__bridge id)kSecAttrService] = accountName;
//    }
//    if ([synchronizable isEqualToString:@"true"]) {
//        search[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kCFBooleanTrue;
//    } else {
//        search[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kCFBooleanFalse;
//    }
//    OSStatus status;
//    status = SecItemDelete((__bridge CFDictionaryRef)search);
//    if (status != noErr){
//        NSLog(@"SecItemDeleteAll status = %d", (int) status);
//    }
//}
//
//- (NSDictionary *)readAll:(NSString *)groupId forAccountName:(NSString *)accountName forSynchronizable:(NSString *)synchronizable {
//    NSMutableDictionary *search = [self.query mutableCopy];
//    if(groupId != nil) {
//        search[(__bridge id)kSecAttrAccessGroup] = groupId;
//    }
//    if(accountName != nil) {
//        search[(__bridge id)kSecAttrService] = accountName;
//    }
//
//    search[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
//
//    search[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
//    search[(__bridge id)kSecReturnAttributes] = (__bridge id)kCFBooleanTrue;
//
//    if ([synchronizable isEqualToString:@"true"]) {
//        search[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kCFBooleanTrue;
//    } else {
//        search[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kCFBooleanFalse;
//    }
//
//    CFArrayRef resultData = NULL;
//
//    OSStatus status;
//    status = SecItemCopyMatching((__bridge CFDictionaryRef)search, (CFTypeRef*)&resultData);
//    if (status == noErr){
//        NSArray *items = (__bridge NSArray*)resultData;
//
//        NSMutableDictionary *results = [[NSMutableDictionary alloc] init];
//        for (NSDictionary *item in items){
//            NSString *key = item[(__bridge NSString *)kSecAttrAccount];
//            NSString *value = [[NSString alloc] initWithData:item[(__bridge NSString *)kSecValueData] encoding:NSUTF8StringEncoding];
//            results[key] = value;
//        }
//        CFRelease(resultData);
//        return [results copy];
//    }
//    return @{};
//}
//
//- (NSNumber *)containsKey:(NSString *)key forGroup:(NSString *)groupId forAccountName:(NSString *)accountName forSynchronizable:(NSString *)synchronizable {
//    NSMutableDictionary *search = [self.query mutableCopy];
//    if(groupId != nil) {
//        search[(__bridge id)kSecAttrAccessGroup] = groupId;
//    }
//    if(accountName != nil) {
//        search[(__bridge id)kSecAttrService] = accountName;
//    }
//    search[(__bridge id)kSecAttrAccount] = key;
//    search[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
//
//    if ([synchronizable isEqualToString:@"true"]) {
//        search[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kCFBooleanTrue;
//    } else {
//        search[(__bridge id)kSecAttrSynchronizable] = (__bridge id)kCFBooleanFalse;
//    }
//
//    if ([search objectForKey:(__bridge id)(kSecAttrAccount)]) {
//        return @YES;
//    } else {
//        return @NO;
//    }
//}
//
//@end
