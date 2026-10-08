@interface LSBundleProxy : NSObject
@property (nonatomic) NSURL *bundleURL;
@property (nonatomic,readonly) NSString *bundleExecutable;
@property (nonatomic,readonly) NSString *bundleIdentifier;
@property (nonatomic,readonly) NSString *localizedName;
@end
