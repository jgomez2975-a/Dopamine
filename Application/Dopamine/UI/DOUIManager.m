//
//  DOUIManager.m
//  Dopamine
//
//  Created by tomt000 on 24/01/2024.
//

#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import "DOThemeManager.h"
#import "DOTheme.h"
#import "NSString+Version.h"
#import <pthread.h>

@implementation DOUIManager

+ (instancetype)sharedInstance
{
    static DOUIManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[DOUIManager alloc] init];
    });
    return sharedInstance;
}

- (id)init
{
    if (self = [super init]){
        _bootlogoPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/bootlogo.png"];
        _preferenceManager = [DOPreferenceManager sharedManager];
        _logRecord = [NSMutableArray new];
        _logLock = [NSLock new];
    }
    return self;
}

- (BOOL)isUpdateAvailable
{
    NSString *latestVersion = [self getLatestReleaseTag];
    NSString *currentVersion = [self getLaunchedReleaseTag];
    return [latestVersion numericalVersionRepresentation] > [currentVersion numericalVersionRepresentation];
}

- (NSArray *)getUpdatesInRange:(NSString *)start end:(NSString *)end
{
    NSArray *releases = [self getLatestReleases];
    if (releases.count == 0)
        return @[];

    long long startVersion = [start numericalVersionRepresentation];
    long long endVersion = [end numericalVersionRepresentation];
    NSMutableArray *updates = [NSMutableArray new];
    for (NSDictionary *release in releases) {
        NSString *version = release[@"tag_name"];
        NSNumber *prerelease = release[@"prerelease"];
        if ([prerelease boolValue]) {
            // Skip prereleases
            continue;
        }
        long long numericalVersion = [version numericalVersionRepresentation];
        if (numericalVersion > startVersion && numericalVersion <= endVersion) {
            [updates addObject:release];
        }
    }
    return updates;
}

- (NSArray *)getLatestReleases
{
    static dispatch_once_t onceToken;
    static NSArray *releases;
    dispatch_once(&onceToken, ^{
        NSURL *url = [NSURL URLWithString:@"https://api.github.com/repos/opa334/Dopamine/releases"];
        NSData *data = [NSData dataWithContentsOfURL:url];
        if (data) {
            NSError *error;
            releases = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:&error];
            if (error)
            {
                onceToken = 0;
                releases = @[];
            }
        }
    });
    return releases;
}

// The staged-basebin token must survive the jailbreak being hidden. It used to live
// in DOPreferenceManager, i.e. /var/mobile/Library/Preferences/com.opa334.Dopamine.plist
// - which runJailbreakLibraryAudit quarantines on purpose. Once that file was moved
// the token read back nil, so environmentUpdateAvailable reported a pending update on
// every single launch and each one ended in another userspace reboot. Keep it in the
// app container instead: the audit never touches it.
- (NSString *)stagedBasebinTokenPath
{
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/staged_basebin_token"];
}

- (NSString *)stagedBasebinToken
{
    return [NSString stringWithContentsOfFile:[self stagedBasebinTokenPath]
                                     encoding:NSUTF8StringEncoding
                                        error:nil];
}

- (NSString *)lastStageAttemptPath
{
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/last_stage_attempt"];
}

- (NSDate *)lastStageAttemptDate
{
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:[self lastStageAttemptPath] error:nil];
    return attrs[NSFileModificationDate];
}
- (BOOL)environmentUpdateAvailable
{
    if (![[DOEnvironmentManager sharedManager] jailbrokenVersion])
        return NO;

    NSString *jailbrokenVersion = [[DOEnvironmentManager sharedManager] jailbrokenVersion];
    NSString *launchedVersion = [self getLaunchedReleaseTag];
    
    if ([launchedVersion numericalVersionRepresentation] > [jailbrokenVersion numericalVersionRepresentation]) {
        return YES;
    }

    // Self-built ipa: the app and the installed basebin carry the SAME version
    // string (3.0.10 == 3.0.10), so the stock comparison above can never become
    // true and the bundled basebin.tar could never be staged - every basebin-side
    // fix stayed dead code. Fall back to fingerprinting the bundled basebin.tar
    // and remembering which one was staged last, so the environment update fires
    // exactly ONCE per distinct basebin build and then stays quiet.
    NSString *token = [self bundledBasebinToken];
    if (!token) return NO;
    if ([token isEqualToString:[self stagedBasebinToken]]) return NO;

    // Safety net: applying a staged basebin ends in a userspace reboot. If the
    // token ever fails to stick, this check would otherwise stage and reboot on
    // every single launch, so never start a second attempt shortly after the last.
    NSDate *lastAttempt = [self lastStageAttemptDate];
    if (lastAttempt) {
        NSTimeInterval elapsed = -[lastAttempt timeIntervalSinceNow];
        if (elapsed >= 0 && elapsed < 600) return NO;
    }

    return YES;
}

// FNV-1a over the bundled basebin.tar: identifies a basebin build without
// depending on the (submodule-owned) version string.
- (NSString *)bundledBasebinToken
{
    NSString *tarPath = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"basebin.tar"];
    NSData *data = [NSData dataWithContentsOfFile:tarPath options:NSDataReadingMappedIfSafe error:nil];
    if (!data || data.length == 0) return nil;

    const uint8_t *bytes = data.bytes;
    NSUInteger len = data.length;
    uint64_t h = 1469598103934665603ULL;
    for (NSUInteger i = 0; i < len; i++) {
        h ^= bytes[i];
        h *= 1099511628211ULL;
    }
    return [NSString stringWithFormat:@"%llu-%llx", (unsigned long long)len, (unsigned long long)h];
}

- (void)markEnvironmentUpdateStaged
{
    NSString *token = [self bundledBasebinToken];
    if (token) {
        [token writeToFile:[self stagedBasebinTokenPath]
                atomically:YES
                  encoding:NSUTF8StringEncoding
                     error:nil];
        [[NSFileManager defaultManager] createFileAtPath:[self lastStageAttemptPath]
                                                contents:[NSData data]
                                              attributes:nil];
    }
}

- (bool)launchedReleaseNeedsManualUpdate
{
    NSString *launchedTag = [self getLaunchedReleaseTag];
    NSDictionary *launchedVersion;
    for (NSDictionary *release in [self getLatestReleases]) {
        if ([release[@"tag_name"] isEqualToString:launchedTag]) {
            launchedVersion = release;
            break;
        }
    }
    if (!launchedVersion)
        return false;
    return [launchedVersion[@"body"] containsString:@"*Manual Updates*"];
}

- (NSString*)getLatestReleaseTag
{
    NSArray *releases = [self getLatestReleases];
    for (NSDictionary *release in releases) {
        NSNumber *prerelease = release[@"prerelease"];
        if ([prerelease boolValue]) {
            continue;
        }
        return release[@"tag_name"];
    }
    return nil;
}

- (NSString*)getLaunchedReleaseTag
{
    return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
}

- (NSArray*)availablePackageManagers
{
    NSString *path = [[NSBundle mainBundle] pathForResource:@"PkgManagers" ofType:@"plist"];
    return [NSArray arrayWithContentsOfFile:path];
}

- (NSArray*)enabledPackageManagerKeys
{
    NSArray *enabledPkgManagers = [_preferenceManager preferenceValueForKey:@"enabledPkgManagers"] ?: @[];
    NSMutableArray *enabledKeys = [NSMutableArray new];
    NSArray *availablePkgManagers = [self availablePackageManagers];

    [availablePkgManagers enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString *key = obj[@"Key"];
        if ([enabledPkgManagers containsObject:key]) {
            [enabledKeys addObject:key];
        }
    }];

    return enabledKeys;
}

- (NSArray*)enabledPackageManagers
{
    NSMutableArray *enabledPkgManagers = [NSMutableArray new];
    NSArray *enabledKeys = [self enabledPackageManagerKeys];

    [[self availablePackageManagers] enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString *key = obj[@"Key"];
        if ([enabledKeys containsObject:key]) {
            [enabledPkgManagers addObject:obj];
        }
    }];

    return enabledPkgManagers;
}

- (void)resetPackageManagers
{
    [_preferenceManager removePreferenceValueForKey:@"enabledPkgManagers"];
}

- (void)resetSettings
{
    [_preferenceManager removePreferenceValueForKey:@"verboseLogsEnabled"];
    [_preferenceManager removePreferenceValueForKey:@"tweakInjectionEnabled"];
    [self resetPackageManagers];
}

- (void)setPackageManager:(NSString*)key enabled:(BOOL)enabled
{
    NSMutableArray *pkgManagers = [self enabledPackageManagerKeys].mutableCopy;
    
    if (enabled && ![pkgManagers containsObject:key]) {
        [pkgManagers addObject:key];
    }
    else if (!enabled && [pkgManagers containsObject:key]) {
        [pkgManagers removeObject:key];
    }

    [_preferenceManager setPreferenceValue:pkgManagers forKey:@"enabledPkgManagers"];
}

- (BOOL)isDebug
{
    NSNumber *debug = [_preferenceManager preferenceValueForKey:@"verboseLogsEnabled"];
    return debug == nil ? NO : [debug boolValue];
}

- (BOOL)enableTweaks
{
    NSNumber *tweaks = [_preferenceManager preferenceValueForKey:@"tweakInjectionEnabled"];
    return tweaks == nil ? YES : [tweaks boolValue];
}

- (void)sendLog:(NSString*)log debug:(BOOL)debug update:(BOOL)update
{
    if (!self.logView || !log)
        return;

    [_logLock lock];

    [self.logRecord addObject:log];

    BOOL isDebug = self.logView.class == DODebugLogView.class;
    if (debug && !isDebug) {
        [_logLock unlock];
        return;
    }
        
    
    if (update) {
        if ([self.logView respondsToSelector:@selector(updateLog:)]) {
            [self.logView updateLog:log];
        }
    }
    else {
        [self.logView showLog:log];
    }
    [_logLock unlock];
}

- (void)sendLog:(NSString*)log debug:(BOOL)debug
{
    [self sendLog:log debug:debug update:NO];
}

- (void)shareLogRecordFromView:(UIView *)sourceView
{
    if (self.logRecord.count == 0)
        return;

    NSString *log = [self.logRecord componentsJoinedByString:@"\n"];
    UIActivityViewController *activityViewController = [[UIActivityViewController alloc] initWithActivityItems:@[log] applicationActivities:nil];
    activityViewController.popoverPresentationController.sourceView = sourceView;
    activityViewController.popoverPresentationController.sourceRect = sourceView.bounds;
    [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:activityViewController animated:YES completion:nil];
}

- (void)completeJailbreak
{
    if (!self.logView)
        return;

    [self.logView didComplete];
}

- (void)observeFileDescriptor:(int)fd withCallback:(void (^)(char *line))callbackBlock
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int stdout_pipe[2];
        int stdout_orig[2];
        if (pipe(stdout_pipe) != 0 || pipe(stdout_orig) != 0) {
            return;
        }

        dup2(fd, stdout_orig[1]);
        close(stdout_orig[0]);
        
        dup2(stdout_pipe[1], fd);
        close(stdout_pipe[1]);
        
        char cur = 0;
        char line[1024];
        int line_index = 0;
        ssize_t bytes_read;

        while ((bytes_read = read(stdout_pipe[0], &cur, sizeof(cur))) > 0) {
            @autoreleasepool {
                write(stdout_orig[1], &cur, bytes_read);

                if (cur == '\n') {
                    line[line_index] = '\0';
                    callbackBlock(line);
                    line_index = 0;
                } else {
                    if (line_index < sizeof(line) - 1) {
                        line[line_index++] = cur;
                    }
                }
            }
        }
        close(stdout_pipe[0]);
    });
}

- (void)startLogCapture
{
    [self observeFileDescriptor:STDOUT_FILENO withCallback:^(char *line) {
        NSString *str = [NSString stringWithUTF8String:line];
        [self sendLog:str debug:YES];
    }];
    
    [self observeFileDescriptor:STDERR_FILENO withCallback:^(char *line) {
        NSString *str = [NSString stringWithUTF8String:line];
        [self sendLog:str debug:YES];
    }];
}

- (NSString *)localizedStringForKey:(NSString*)key
{
    NSString *candidate = NSLocalizedString(key, nil);
    if ([candidate isEqualToString:key]) {
        if (!_fallbackLocalizations) {
            _fallbackLocalizations = [NSDictionary dictionaryWithContentsOfFile:[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"en.lproj/Localizable.strings"]];
        }
        candidate = _fallbackLocalizations[key];
        if (!candidate) candidate = key;
    }
    return candidate;
}

- (UIImage *)renderBootLogo
{
    return [[[DOThemeManager sharedInstance] enabledTheme] generateBootLogo];
}

@end


NSString *DOLocalizedString(NSString *key)
{
    return [[DOUIManager sharedInstance] localizedStringForKey:key];
}
