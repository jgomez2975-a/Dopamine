#import "hide_global.h"
#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/util.h>
#import <sys/stat.h>
#import <errno.h>

// ---------------------------------------------------------------------------
// URL scheme hiding (ported from DOEnvironmentManager.m)
// ---------------------------------------------------------------------------

static NSString *findAppPathForBundleName(NSString *appName)
{
	NSFileManager *fm = [NSFileManager defaultManager];
	NSArray<NSString *> *roots = @[@"/var/containers/Bundle/Application", @"/Applications"];
	for (NSString *root in roots) {
		NSArray *uuids = [fm contentsOfDirectoryAtPath:root error:nil];
		for (NSString *uuid in uuids) {
			NSString *uuidPath = [root stringByAppendingPathComponent:uuid];
			NSArray *contents = [fm contentsOfDirectoryAtPath:uuidPath error:nil];
			for (NSString *item in contents) {
				if ([item isEqualToString:appName]) {
					NSString *fullPath = [uuidPath stringByAppendingPathComponent:item];
					BOOL isDir = NO;
					if ([fm fileExistsAtPath:fullPath isDirectory:&isDir] && isDir) {
						return fullPath;
					}
				}
			}
		}
	}
	return nil;
}

static BOOL hideURLScheme(NSString *scheme, NSString *appPath)
{
	NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
	NSFileManager *fm = [NSFileManager defaultManager];
	if (![fm fileExistsAtPath:infoPlistPath]) return NO;

	NSData *data = [NSData dataWithContentsOfFile:infoPlistPath];
	if (!data) return NO;

	id parsed = [NSPropertyListSerialization propertyListWithData:data
	                                                      options:NSPropertyListMutableContainersAndLeaves
	                                                       format:NULL
	                                                        error:nil];
	if (![parsed isKindOfClass:[NSMutableDictionary class]]) return NO;

	NSMutableDictionary *plist = (NSMutableDictionary *)parsed;
	BOOL modified = NO;

	NSArray *urlTypes = plist[@"CFBundleURLTypes"];
	if ([urlTypes isKindOfClass:[NSArray class]]) {
		NSMutableArray *newUrlTypes = [NSMutableArray array];
		for (NSDictionary *urlType in urlTypes) {
			NSArray *schemes = urlType[@"CFBundleURLSchemes"];
			if ([schemes isKindOfClass:[NSArray class]] && [schemes containsObject:scheme]) {
				NSMutableDictionary *newUrlType = [urlType mutableCopy];
				NSMutableArray *newSchemes = [schemes mutableCopy];
				[newSchemes removeObject:scheme];
				if (newSchemes.count > 0) {
					newUrlType[@"CFBundleURLSchemes"] = newSchemes;
					[newUrlTypes addObject:newUrlType];
				}
				modified = YES;
			} else {
				[newUrlTypes addObject:urlType];
			}
		}
		if (modified) plist[@"CFBundleURLTypes"] = newUrlTypes;
	}

	NSArray *queriesSchemes = plist[@"LSApplicationQueriesSchemes"];
	if ([queriesSchemes isKindOfClass:[NSArray class]] && [queriesSchemes containsObject:scheme]) {
		NSMutableArray *newQueries = [queriesSchemes mutableCopy];
		[newQueries removeObject:scheme];
		plist[@"LSApplicationQueriesSchemes"] = newQueries;
		modified = YES;
	}

	if (!modified) return NO;

	NSString *backupPath = [infoPlistPath stringByAppendingString:@".hideurl_backup"];
	if (![fm fileExistsAtPath:backupPath]) {
		if (![fm copyItemAtPath:infoPlistPath toPath:backupPath error:nil]) return NO;
	}

	NSData *outData = [NSPropertyListSerialization dataWithPropertyList:plist
	                                                             format:NSPropertyListXMLFormat_v1_0
	                                                            options:0
	                                                              error:nil];
	if (!outData) return NO;
	return [outData writeToFile:infoPlistPath options:NSDataWritingAtomic error:nil];
}

static void restoreURLSchemeForAppAtPath(NSString *appPath)
{
	NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
	NSString *backupPath = [infoPlistPath stringByAppendingString:@".hideurl_backup"];
	NSFileManager *fm = [NSFileManager defaultManager];
	if (![fm fileExistsAtPath:backupPath]) return;

	[fm removeItemAtPath:infoPlistPath error:nil];
	[fm copyItemAtPath:backupPath toPath:infoPlistPath error:nil];
	[fm removeItemAtPath:backupPath error:nil];
}

static void refreshURLSchemeApps(NSArray<NSString *> *appPaths)
{
	for (NSString *appPath in appPaths) {
		exec_cmd(JBROOT_PATH("/usr/bin/uicache"), "-p", appPath.fileSystemRepresentation, NULL);
	}
}

static void hideJailbreakURLSchemes(void)
{
	NSDictionary<NSString *, NSArray<NSString *> *> *targets = @{
		@"Reveil.app":    @[@"reveil", @"82flex"],
		@"PostBox.app":   @[@"postbox"],
		@"Santander.app": @[@"santander"],
		@"Cowabunga.app": @[@"cowabunga"],
		@"misaka.app":    @[@"misaka"],
	};

	NSMutableArray<NSString *> *touchedApps = [NSMutableArray array];
	for (NSString *appName in targets) {
		NSString *appPath = findAppPathForBundleName(appName);
		if (!appPath) continue;
		BOOL anyModified = NO;
		for (NSString *scheme in targets[appName]) {
			if (hideURLScheme(scheme, appPath)) anyModified = YES;
		}
		if (anyModified) [touchedApps addObject:appPath];
	}
	if (touchedApps.count > 0) refreshURLSchemeApps(touchedApps);
}

static void restoreJailbreakURLSchemes(void)
{
	NSArray<NSString *> *appNames = @[@"Reveil.app", @"PostBox.app", @"Santander.app", @"Cowabunga.app", @"Misaka.app"];
	NSMutableArray<NSString *> *touchedApps = [NSMutableArray array];
	for (NSString *appName in appNames) {
		NSString *appPath = findAppPathForBundleName(appName);
		if (!appPath) continue;
		NSString *backupPath = [[appPath stringByAppendingPathComponent:@"Info.plist"] stringByAppendingString:@".hideurl_backup"];
		if ([[NSFileManager defaultManager] fileExistsAtPath:backupPath]) {
			restoreURLSchemeForAppAtPath(appPath);
			[touchedApps addObject:appPath];
		}
	}
	if (touchedApps.count > 0) refreshURLSchemeApps(touchedApps);
}

// ---------------------------------------------------------------------------
// Jailbreak library audit / quarantine (ported from DOEnvironmentManager.m)
// ---------------------------------------------------------------------------

#import "../../../Shared/JBQuarantine.h"

static BOOL doAuditName(NSString *name, NSArray<NSString *> *exact, NSArray<NSString *> *regex)
{
	if ([exact containsObject:name]) return YES;
	for (NSString *pattern in regex) {
		NSRegularExpression *expression = [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:nil];
		if ([expression firstMatchInString:name options:0 range:NSMakeRange(0, name.length)]) return YES;
	}
	return NO;
}

static int runJailbreakLibraryAudit(void)
{
	NSFileManager *fm = [NSFileManager defaultManager];

	NSDictionary<NSString *, NSDictionary *> *rules = @{
		@"/var/mobile/Library": @{
			@"whitelist": @[@"Accessibility", @"CoreBrightness", @"Keyboard", @"Preferences", @"Voicemail", @"Accounts", @"CoreDuet", @"KeyboardServices", @"PrivacyAccounting", @"WatchConnectivity", @"AddressBook", @"CoreFollowUp", @"LASD", @"Recents", @"Weather", @"AggregateDictionary", @"CountryModeling", @"Reminders", @"WebClips", @"CrashReporter", @"Logs", @"ReplayKit", @"WebKit", @"Application Support", @"MediaRemote", @"Safari", @"Caches", @"SplashBoard", @"MobileInstallation", @"SoftwareUpdate", @"BulletinBoard", @"MobileContainerManager", @"TCC", @"Settings", @"Cookies", @"Passes", @"UserNotifications", @"ApplicationSync", @"DataDeliveryServices", @"MediaStream", @"SafeHarbor", @"Wallet", @"Maps", @"Phone"],
			@"blacklist": @[@"Sileo", @"Filza", @"Flex3", @"SBSettings", @"iCleaner", @"AppTools", @"RootHide", @"NiceiOS", @"Cydia"]
		},
		@"/var/mobile/Library/Preferences": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\.", @"^systemgroup\\.com\\.apple\\."],
			@"whitelist": @[@".GlobalPreferences.plist", @".GlobalPreferences_m.plist", @"bluetoothaudiod.plist", @"NetworkInterfaces.plist", @"OSThermalStatus.plist", @"preferences.plist", @"osanalyticshelper.plist", @"UserEventAgent.plist", @"wifid.plist", @"dprivacyd.plist", @"silhouette.plist", @"nfcd.plist", @"ptpcamerad.plist", @"mobile_storage_proxy.plist", @".DopamineAppHideRules.plist", @".DopamineInjectionRules.plist"],
			@"blacklist": @[@"com.roothide.manager.plist", @"com.opa334.Dopamine.roothide.plist", @"com.opa334.Dopamine.plist", @"com.tigisoftware.Filza.plist", @"com.xina.jailbreak.plist", @"org.coolstar.SileoStore.plist", @"ru.domo.cocoatop64.plist", @"ws.hbang.Terminal.plist", @"xyz.willy.Zebra.plist", @"com.apple.terminal.plist"]
		},
		@"/var/mobile/Library/Application Support": @{
			@"blacklist": @[@"xyz.willy.Zebra"]
		},
		@"/var/mobile/Library/Application Support/Containers": @{
			@"default": @"blacklist",
			@"blacklist": @[@"xyz.willy.Zebra", @"com.tigisoftware.Filza", @"org.coolstar.SileoStore", @"com.apple.Terminal"]
		},
		@"/var/mobile/Library/UserConfigurationProfiles/PublicInfo": @{
			@"blacklist": @[@"Flex3Patches.plist"]
		},
		@"/var/mobile/Library/SplashBoard/Snapshots": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\."],
			@"blacklist": @[@"com.roothide.manager", @"com.opa334.Dopamine.roothide", @"com.opa334.Dopamine", @"com.tigisoftware.Filza", @"org.coolstar.SileoStore", @"ru.domo.cocoatop64", @"ws.hbang.Terminal", @"xyz.willy.Zebra", @"com.apple.Terminal"]
		},
		@"/var/mobile/Library/Caches": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\.", @"^TelephonyUI-\\d+$", @"^FamilyMarquee.*Mode-.*\\.png$"],
			@"whitelist": @[@"CloudKit", @"GameKit", @"GeoServices", @"FamilyCircle", @"PassKit", @"VoiceServices", @"VoiceTrigger", @"Backup", @"ssu"],
			@"blacklist": @[@"com.opa334.Dopamine", @"com.tigisoftware.Filza", @"org.coolstar.SileoStore", @"ws.hbang.Terminal", @"xyz.willy.Zebra", @"Cephei", @"com.apple.Terminal", @"GDFileManagerCache.sqlite", @"GDFileManagerCache.sqlite-shm", @"GDFileManagerCache.sqlite-wal", @"ImageTables", @"SentryCrash", @"io.sentry", @"com.hackemist.SDImageCache"]
		},
		@"/var/mobile/Library/Saved Application State": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\."],
			@"blacklist": @[@"com.opa334.Dopamine.savedState", @"com.tigisoftware.Filza.savedState", @"org.coolstar.SileoStore.savedState", @"ws.hbang.Terminal.savedState", @"xyz.willy.Zebra.savedState", @"ru.domo.cocoatop64.savedState", @"com.apple.Terminal.savedState"]
		},
		@"/var/mobile/Library/WebKit": @{
			@"whitelist": @[@"Databases", @"LocalStorage"],
			@"whitelistRegex": @[@"^com\\.apple\\."],
			@"blacklist": @[@"xyz.willy.Zebra"]
		},
		@"/var/mobile/Library/Cookies": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\."],
			@"whitelist": @[@"Cookies.binarycookies"],
			@"blacklist": @[@"com.johncoates.Flex.binarycookies"]
		},
		@"/var/mobile/Library/HTTPStorages": @{
			@"default": @"blacklist",
			@"whitelistRegex": @[@"^com\\.apple\\."],
			@"blacklist": @[@"com.opa334.Dopamine", @"com.tigisoftware.Filza", @"org.coolstar.SileoStore", @"ws.hbang.Terminal", @"xyz.willy.Zebra"]
		},
		@"/var/mobile/Documents": @{
			@"blacklist": @[@"DumpDecrypter", @"Dumplpa", @"wiki.qaq.chromatic", @"TheosProject", @"DebBackup", @"Settings_Customizer", @"Background_Files", @"ProGestureConfigs", @"Saved_Fonts", @"Included_Audio", @"Saved_Operations", @"Saved_Locks", @"Anilaunch", @"AD-deb", @"Debra", @".Xinaf1re", @"PerfectDynamiclsland", @"Cowabunga_Audio", @".DynamicCowBackups", @".PlampyUIPro"]
		},
		@"/var/mobile": @{
			@"blacklist": @[@".DO-NOT-DELETE-Cowabunga", @".Derootifier", @"Helix", @".ssh", @".cache"]
		}
	};

	NSArray<NSString *> *paths = [rules.allKeys sortedArrayUsingSelector:@selector(compare:)];
	for (NSString *path in paths) {
		if (![fm fileExistsAtPath:path]) continue;
		NSDictionary *rule = rules[path];
		NSString *defaultAction = rule[@"default"];
		NSArray *whitelist = rule[@"whitelist"] ?: @[];
		NSArray *blacklist = rule[@"blacklist"] ?: @[];
		NSArray *whitelistRegex = rule[@"whitelistRegex"] ?: @[];
		NSArray<NSString *> *children = [fm contentsOfDirectoryAtPath:path error:nil];
		if (!children) return EIO;

		for (NSString *name in children) {
			BOOL white = doAuditName(name, whitelist, whitelistRegex);
			BOOL black = [blacklist containsObject:name];
			NSString *result = nil;
			if (black) result = @"BLACKLIST";
			else if (white) result = @"WHITELIST";
			else if (defaultAction) result = [defaultAction isEqualToString:@"blacklist"] ? @"DEFAULT-BLACKLIST" : @"DEFAULT-WHITELIST";
			else result = @"UNMATCHED";

			BOOL shouldHide = [result isEqualToString:@"BLACKLIST"] || [result isEqualToString:@"DEFAULT-BLACKLIST"];
			if (shouldHide) {
				int result = hideItemAtPath([path stringByAppendingPathComponent:name]);
				if (result != 0) return result;
			}
		}
	}

	for (NSString *name in @[@".misaka"]) {
		NSString *fullPath = [@"/var/mobile/Documents" stringByAppendingPathComponent:name];
		if ([fm fileExistsAtPath:fullPath]) {
			int result = hideItemAtPath(fullPath);
			if (result != 0) return result;
		}
	}
	return 0;
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

int hide_global_urlschemes_hide(void)
{
	@autoreleasepool { hideJailbreakURLSchemes(); }
	return 0;
}

int hide_global_urlschemes_show(void)
{
	@autoreleasepool { restoreJailbreakURLSchemes(); }
	return 0;
}

int hide_global_audit_hide(void)
{
 @autoreleasepool {
  return auditWithLock(^int {
   auditLog(@"=== audit hide START ===");
   int result = runJailbreakLibraryAudit();
   if (result != 0) {
    int rollback = restoreHiddenItems();
    auditLog([NSString stringWithFormat:@"audit_transaction_v2: hide failed=%d rollback=%d", result, rollback]);
   }
   auditLog([NSString stringWithFormat:@"=== audit hide END result=%d ===", result]);
   return result;
  });
 }
}

int hide_global_audit_restore(void)
{
 @autoreleasepool {
  return auditWithLock(^int {
   auditLog(@"=== audit restore START ===");
   int result = restoreHiddenItems();
   auditLog([NSString stringWithFormat:@"=== audit restore END result=%d ===", result]);
   return result;
  });
 }
}
