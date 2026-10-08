#include "jbsettings.h"
#include <libjailbreak/info.h>
#include <libjailbreak/jbclient_xpc.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/stat.h>

static int persist_process_blacklist(xpc_object_t value)
{
	if (!value || xpc_get_type(value) != XPC_TYPE_ARRAY) return -1;

	CFMutableArrayRef paths = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
	xpc_array_apply(value, ^bool(size_t index, xpc_object_t object) {
		if (xpc_get_type(object) == XPC_TYPE_STRING) {
			CFStringRef path = CFStringCreateWithCString(kCFAllocatorDefault, xpc_string_get_string_ptr(object), kCFStringEncodingUTF8);
			if (path) { CFArrayAppendValue(paths, path); CFRelease(path); }
		}
		return true;
	});

	char configPath[PATH_MAX];
	char *jbroot = jbclient_get_jbroot();
	if (!jbroot) return -1;
	snprintf(configPath, sizeof(configPath), "%s/basebin/config.plist", jbroot);
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)configPath, strlen(configPath), false);
	CFMutableDictionaryRef config = NULL;
	CFDataRef input = NULL;
	SInt32 error = 0;
	if (url && CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault, url, &input, NULL, NULL, &error) && input) {
		CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault, input, kCFPropertyListMutableContainersAndLeaves, NULL, NULL);
		if (plist && CFGetTypeID(plist) == CFDictionaryGetTypeID()) config = (CFMutableDictionaryRef)plist;
		else if (plist) CFRelease(plist);
	}
	if (!config) config = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFStringRef key = CFSTR("ProcessBlacklist");
	CFDictionarySetValue(config, key, paths);
	CFDataRef output = CFPropertyListCreateData(kCFAllocatorDefault, config, kCFPropertyListBinaryFormat_v1_0, 0, NULL);
	Boolean ok = output && url && CFURLWriteDataAndPropertiesToResource(url, output, NULL, &error);
	if (output) CFRelease(output);
	if (config) CFRelease(config);
	if (input) CFRelease(input);
	if (url) CFRelease(url);
	CFRelease(paths);
	return ok ? 0 : -1;
}

int jbsettings_get(const char *key, xpc_object_t *valueOut)
{
	if (!key)	return -1;

	if (!strcmp(key, "markAppsAsDebugged")) {
		*valueOut = xpc_bool_create(jbsetting(markAppsAsDebugged));
		return 0;
	}
	else if (!strcmp(key, "jetsamMultiplier")) {
		*valueOut = xpc_double_create(jbsetting(jetsamMultiplier));
		return 0;
	}
	return -1;
}

int jbsettings_set(const char *key, xpc_object_t value)
{
	if (!strcmp(key, "markAppsAsDebugged") && xpc_get_type(value) == XPC_TYPE_BOOL) {
		gSystemInfo.jailbreakSettings.markAppsAsDebugged = xpc_bool_get_value(value);
		return 0;
	}
	else if (!strcmp(key, "jetsamMultiplier") && xpc_get_type(value) == XPC_TYPE_DOUBLE) {
		gSystemInfo.jailbreakSettings.jetsamMultiplier = xpc_double_get_value(value);
		return 0;
	}
	else if (!strcmp(key, "ProcessBlacklist")) {
		return persist_process_blacklist(value);
	}
	return -1;
}
