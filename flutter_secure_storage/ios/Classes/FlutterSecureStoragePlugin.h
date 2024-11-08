//#import <Flutter/Flutter.h>
//
//@interface FlutterSecureStoragePlugin : NSObject<FlutterPlugin>
//- (void)write:(NSString *)value forKey:(NSString *)key forGroup:(NSString *)groupId accessibilityAttr:(NSString *)accessibility forAccountName:(NSString *)accountName forSynchronizable:(NSString *)synchronizable;
//-(NSString *)read:(NSString *)key forGroup:(NSString *)groupId forAccountName:(NSString *)accountName forSynchronizable:(NSString *)synchronizable;
//-(void)delete:(NSString *)key forGroup:(NSString *)groupId forAccountName:(NSString *)accountName forSynchronizable:(NSString *)synchronizable;
//-(NSDictionary *)readAll:(NSString *)groupId forAccountName:(NSString *)accountName forSynchronizable:(NSString *)synchronizable;
//-(NSNumber *)containsKey:(NSString *)key forGroup:(NSString *)groupId forAccountName:(NSString *)accountName forSynchronizable:(NSString *)synchronizable;
//@end

#import <Flutter/Flutter.h>

@interface FlutterSecureStoragePlugin : NSObject<FlutterPlugin>
@end
