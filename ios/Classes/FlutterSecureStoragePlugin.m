#import "FlutterSecureStoragePlugin.h"

static NSString *const KEYCHAIN_SERVICE = @"flutter_secure_storage_service";
static NSString *const CHANNEL_NAME = @"plugins.it_nomads.com/flutter_secure_storage";

static NSString *const InvalidParameters = @"Invalid parameter's type";

@interface FlutterSecureStoragePlugin()

@property (strong, nonatomic) NSDictionary *query;

@end

@implementation FlutterSecureStoragePlugin

- (instancetype)init {
    self = [super init];
    if (self){
        self.query = @{
                       (__bridge id)kSecClass :(__bridge id)kSecClassGenericPassword,
                       (__bridge id)kSecAttrService :KEYCHAIN_SERVICE,
                       };
    }
    return self;
}

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
    FlutterMethodChannel* channel = [FlutterMethodChannel
                                     methodChannelWithName:CHANNEL_NAME
                                     binaryMessenger:[registrar messenger]];
    FlutterSecureStoragePlugin* instance = [[FlutterSecureStoragePlugin alloc] init];
    [registrar addMethodCallDelegate:instance channel:channel];
}

- (void)handleMethodCall:(FlutterMethodCall*)call result:(FlutterResult)result {
    NSDictionary *arguments = [call arguments];

    if ([@"read" isEqualToString:call.method]) {
        NSString *key = arguments[@"key"];
        NSString *groupId = arguments[@"groupId"];
        NSString *value = [self read:key forGroup:groupId];
        
        result(value);
    } else
    if ([@"write" isEqualToString:call.method]) {
        NSString *key = arguments[@"key"];
        NSString *value = arguments[@"value"];
        NSString *groupId = arguments[@"groupId"];
        if (![value isKindOfClass:[NSString class]]){
            result(InvalidParameters);
            return;
        }
        
        [self write:value forKey:key forGroup:groupId];
        
        result(nil);
    } else if ([@"delete" isEqualToString:call.method]) {
        NSString *key = arguments[@"key"];
        NSString *groupId = arguments[@"groupId"];
        [self delete:key forGroup:groupId];
        
        result(nil);
    } else if ([@"deleteAll" isEqualToString:call.method]) {
        NSString *groupId = arguments[@"groupId"];
        [self deleteAll: groupId];
        
        result(nil);
    } else if ([@"readAll" isEqualToString:call.method]) {
        NSString *groupId = arguments[@"groupId"];
        NSDictionary *value = [self readAll: groupId];

        result(value);
    }else {
        result(FlutterMethodNotImplemented);
    }
}

- (void)write:(NSString *)value forKey:(NSString *)key forGroup:(NSString *)groupId {
    NSMutableDictionary *search = [self.query mutableCopy];
    if(groupId != nil) {
        search[(__bridge id)kSecAttrAccessGroup] = groupId;
    }
    search[(__bridge id)kSecAttrAccount] = key;
    search[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    
    OSStatus status;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)search, NULL);
    if (status == noErr){
        search[(__bridge id)kSecMatchLimit] = nil;
        
        NSDictionary *update = @{(__bridge id)kSecValueData: [value dataUsingEncoding:NSUTF8StringEncoding]};
        
        status = SecItemUpdate((__bridge CFDictionaryRef)search, (__bridge CFDictionaryRef)update);
        if (status != noErr){
            NSLog(@"SecItemUpdate status = %d", status);
        }
    }else{
        search[(__bridge id)kSecValueData] = [value dataUsingEncoding:NSUTF8StringEncoding];
        search[(__bridge id)kSecMatchLimit] = nil;
        
        status = SecItemAdd((__bridge CFDictionaryRef)search, NULL);
        if (status != noErr){
            NSLog(@"SecItemAdd status = %d", status);
        }
    }
}

- (NSString *)read:(NSString *)key forGroup:(NSString *)groupId {
    NSMutableDictionary *search = [self.query mutableCopy];
    if(groupId != nil) {
     search[(__bridge id)kSecAttrAccessGroup] = groupId;
    }
    search[(__bridge id)kSecAttrAccount] = key;
    search[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
    
    CFDataRef resultData = NULL;
    
    OSStatus status;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)search, (CFTypeRef*)&resultData);
    NSString *value;
    if (status == noErr){
        NSData *data = (__bridge NSData*)resultData;
        value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    
    return value;
}

- (void)delete:(NSString *)key forGroup:(NSString *)groupId {
    NSMutableDictionary *search = [self.query mutableCopy];
    if(groupId != nil) {
        search[(__bridge id)kSecAttrAccessGroup] = groupId;
    }
    search[(__bridge id)kSecAttrAccount] = key;
    search[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;
    
    SecItemDelete((__bridge CFDictionaryRef)search);
}

- (void)deleteAll:(NSString *)groupId {
    NSMutableDictionary *search = [self.query mutableCopy];
    if(groupId != nil) {
        search[(__bridge id)kSecAttrAccessGroup] = groupId;
    }
    SecItemDelete((__bridge CFDictionaryRef)search);
}

- (NSDictionary *)readAll:(NSString *)groupId {
    NSMutableDictionary *search = [self.query mutableCopy];
    if(groupId != nil) {
        search[(__bridge id)kSecAttrAccessGroup] = groupId;
    }
    
    search[(__bridge id)kSecReturnData] = (__bridge id)kCFBooleanTrue;

    search[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    search[(__bridge id)kSecReturnAttributes] = (__bridge id)kCFBooleanTrue;

    CFArrayRef resultData = NULL;
    
    OSStatus status;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)search, (CFTypeRef*)&resultData);
    if (status == noErr){
        NSArray *items = (__bridge NSArray*)resultData;
        
        NSMutableDictionary *results = [[NSMutableDictionary alloc] init];
        for (NSDictionary *item in items){
            NSString *key = item[(__bridge NSString *)kSecAttrAccount];
            NSString *value = [[NSString alloc] initWithData:item[(__bridge NSString *)kSecValueData] encoding:NSUTF8StringEncoding];
            results[key] = value;
        }
        return [results copy];
    }
    
    return @{};
}

@end
