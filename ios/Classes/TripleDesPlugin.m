#import "TripleDesPlugin.h"
#if __has_include(<triple_des/triple_des-Swift.h>)
#import <triple_des/triple_des-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "triple_des-Swift.h"
#endif

@implementation TripleDesPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftTripleDesPlugin registerWithRegistrar:registrar];
}
@end
