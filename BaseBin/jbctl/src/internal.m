#import "internal.h"
#import "hide_global.h"
#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/developer_mode_hide.h>
#import <sys/mount.h>
#import <libjailbreak/stock_fixes.h>
#include <string.h>
#include <stdarg.h>
#include <sys/sysctl.h>

SInt32 CFUserNotificationDisplayAlert(CFTimeInterval timeout, CFOptionFlags flags, CFURLRef iconURL, CFURLRef soundURL, CFURLRef localizationURL, CFStringRef alertHeader, CFStringRef alertMessage, CFStringRef defaultButtonTitle, CFStringRef alternateButtonTitle, CFStringRef otherButtonTitle, CFOptionFlags *responseFlags) API_AVAILABLE(ios(3.0));

void execute_unsandboxed(void (^block)(void))
{
	uint64_t credBackup = 0;
	jbclient_root_steal_ucred(0, &credBackup);
	block();
	jbclient_root_steal_ucred(credBackup, NULL);
}

int mount_unsandboxed(const char *type, const char *dir, int flags, void *data)
{
	__block int r = 0;
	execute_unsandboxed(^{
		r = mount(type, dir, flags, data);
	});
	return r;
}

int unmount_unsandboxed(const char *dir, int flags)
{
	__block int r = 0;
	execute_unsandboxed(^{
		r = unmount(dir, flags);
	});
	return r;
}

bool is_protected(const char *path)
{
	struct statfs sb;
	statfs(path, &sb);
	return strcmp(path, sb.f_mntonname) == 0;
}

int ensure_protected(const char *path)
{
	if (!is_protected(path)) {
		return mount_unsandboxed("bindfs", path, 0, (void *)path);
	}
	return 0;
}

int ensure_unprotected(const char *path)
{
	if (is_protected(path)) {
		return unmount_unsandboxed(path, MNT_FORCE);
	}
	return 0;
}

int protection_set_active(bool active)
{
	int r = 0;
	if (active) {
		// Protect /private/preboot/UUID/<System, usr> from being modified by bind mounting them on top of themselves
		// This protects dumb users from accidentally deleting these, which would induce a recovery loop after rebooting
		r |= ensure_protected(prebootUUIDPath("/System"));
		r |= ensure_protected(prebootUUIDPath("/usr"));
	}
	else {
		r |= ensure_unprotected(prebootUUIDPath("/System"));
		r |= ensure_unprotected(prebootUUIDPath("/usr"));
	}
	return r;
}

bool fakelib_is_mounted(void)
{
	struct statfs fsb;
    if (statfs("/usr/lib", &fsb) != 0) return NO;
    return strcmp(fsb.f_mntonname, "/usr/lib") == 0;
}

int fakelib_set_mounted(bool mounted)
{
	int r = 0;
	if (mounted != fakelib_is_mounted()) {
		if (mounted) {
			r = mount_unsandboxed("bindfs", "/usr/lib", MNT_RDONLY, (void *)JBROOT_PATH("/basebin/.fakelib"));
		}
		else {
			r = unmount_unsandboxed("/usr/lib", MNT_FORCE);
		}
	}
	return r;
}

bool fakePath_is_mounted(const char *path)
{
	struct statfs fsb;
    if (statfs(path, &fsb) != 0) return NO;
    return strcmp(fsb.f_mntonname, path) == 0;
}

void initMountPath(NSString *mountPath)
{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    bool new = NO;

    if([fileManager fileExistsAtPath:mountPath]){
        NSString *newPath = [NSString stringWithFormat:@"%@%@", JBROOT_PATH(@"/mnt"), mountPath];

        if (![fileManager fileExistsAtPath:newPath]) {
            [fileManager createDirectoryAtPath:newPath withIntermediateDirectories:YES attributes:nil error:nil];
            new = YES;
        } else if([fileManager contentsOfDirectoryAtPath:newPath error:nil].count == 0){
            new = YES;
        }

        if(new){
            NSString *tmpPath = [NSString stringWithFormat:@"%@_tmp", newPath];
            [fileManager copyItemAtPath:mountPath toPath:tmpPath error:nil];
            [fileManager removeItemAtPath:newPath error:nil];
            [fileManager moveItemAtPath:tmpPath toPath:newPath error:nil];
        }
    }
}

int fakePath_mount(bool mount, const char *path)
{
	int r = 0;
	if (mount != fakePath_is_mounted(path)) {
		if (mount) {
			initMountPath([NSString stringWithUTF8String:path]);
			NSString *newMountPath = [NSString stringWithFormat:@"%@%s", JBROOT_PATH(@"/mnt"), path];
			r = mount_unsandboxed("bindfs", path, MNT_RDONLY, (void *)newMountPath.UTF8String);
		}
		else {
			r = unmount_unsandboxed(path, MNT_FORCE);
		}
	}
	return r;
}

// ---------------------------------------------------------------------------
// probe_sysctl: locate the two AMFI sysctl OIDs in the kernel, so we can later
// swap their handlers (RootHide-style: report developer mode as 0 without
// touching the real state). Prints everything needed for that swap.
// ---------------------------------------------------------------------------
static uint64_t probe_find_oid(const char *shortName, uint64_t base, uint64_t scanSize, uint64_t *nameStrOut)
{
	size_t targetLen = strlen(shortName);
	uint8_t *page = malloc(0x1000);
	*nameStrOut = 0;
	if (!page) return 0;

	uint64_t strAddr = 0;
	for (uint64_t addr = base; addr < base + scanSize; addr += 0x1000) {
		if (kreadbuf(addr, page, 0x1000) != 0) continue;
		for (int off = 0; off + (int)targetLen + 1 <= 0x1000; off++) {
			if (memcmp(page + off, shortName, targetLen) == 0 && page[off + targetLen] == 0) {
				strAddr = addr + off;
				break;
			}
		}
		if (strAddr) break;
	}
	if (!strAddr) { free(page); return 0; }

	uint64_t oid = 0;
	for (uint64_t addr = base; addr < base + scanSize && !oid; addr += 0x1000) {
		if (kreadbuf(addr, page, 0x1000) != 0) continue;
		for (int off = 0; off + 8 <= 0x1000; off += 8) {
			if (*(uint64_t *)(page + off) == strAddr) {
				oid = addr + off - 48; // oid_name @ +48
				*nameStrOut = strAddr;
				break;
			}
		}
	}
	free(page);
	return oid;
}

static int probe_read_int(const char *name)
{
	int val = -999;
	size_t len = sizeof(val);
	sysctlbyname(name, &val, &len, NULL, 0);
	return val;
}

static void probe_sysctl_oids(void)
{
	uint64_t base = gSystemInfo.kernelConstant.base;
	uint64_t slide = gSystemInfo.kernelConstant.slide;
	uint64_t scanSize = 0x4000000ULL; // 64 MB from kernel base

	printf("base=0x%llx slide=0x%llx\n", (unsigned long long)base, (unsigned long long)slide);
	fflush(stdout);

	uint64_t devName = 0, launchName = 0;
	uint64_t devOid = probe_find_oid("developer_mode_status", base, scanSize, &devName);
	uint64_t launchOid = probe_find_oid("launch_env_logging", base, scanSize, &launchName);

	printf("devOid=0x%llx (off 0x%llx) devNameStr=0x%llx (off 0x%llx)\n",
		   (unsigned long long)devOid, (unsigned long long)(devOid - base),
		   (unsigned long long)devName, (unsigned long long)(devName - base));
	printf("launchOid=0x%llx (off 0x%llx) launchNameStr=0x%llx (off 0x%llx)\n",
		   (unsigned long long)launchOid, (unsigned long long)(launchOid - base),
		   (unsigned long long)launchName, (unsigned long long)(launchName - base));
	fflush(stdout);

	if (!devOid || !launchOid) { printf("OID not found, abort swap test\n"); fflush(stdout); return; }

	printf("=== swap test ===\n");
	printf("  before: devmode_status=%d\n", probe_read_int("security.mac.amfi.developer_mode_status"));
	fflush(stdout);

	// swap the two oid_name pointers (data pointers, no PAC)
	kwrite64(devOid + 48, launchName);
	kwrite64(launchOid + 48, devName);

	printf("  after swap: devmode_status=%d (expect 0)\n", probe_read_int("security.mac.amfi.developer_mode_status"));
	printf("  after swap: launch_env_logging=%d\n", probe_read_int("security.mac.amfi.launch_env_logging"));
	fflush(stdout);

	// restore
	kwrite64(devOid + 48, devName);
	kwrite64(launchOid + 48, launchName);

	printf("  after restore: devmode_status=%d (expect 1)\n", probe_read_int("security.mac.amfi.developer_mode_status"));
	fflush(stdout);
}

// RootHide-style developer-mode hiding that does NOT touch the real state:
// swap the two AMFI sysctl OIDs' name pointers so that
// sysctlbyname("security.mac.amfi.developer_mode_status") resolves to the
// launch_env_logging OID (which reads 0), while the real developer-mode storage
// byte is left untouched. Offsets (relative to the kernel image base) were
// located with `probe_sysctl` on iPhone 15 Pro Max / iOS 17.0.3.
#define DEVMODE_DEV_OID_OFF     0x3651ed8ULL
#define DEVMODE_DEV_NAME_OFF    0x3f189cULL
#define DEVMODE_LAUNCH_OID_OFF  0x3652068ULL
#define DEVMODE_LAUNCH_NAME_OFF 0x3f19ebULL

static void oidswap_log(const char *fmt, ...)
{
	FILE *f = fopen("/var/mobile/Documents/noinject_log.txt", "a");
	if (!f) return;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fclose(f);
}

static int devmode_oidswap(bool hide)
{
	uint64_t base = gSystemInfo.kernelConstant.base;
	oidswap_log("oidswap: enter hide=%d base=0x%llx\n", hide, (unsigned long long)base);
	if (!base) return -1;

	uint64_t devOid     = base + DEVMODE_DEV_OID_OFF;
	uint64_t devName    = base + DEVMODE_DEV_NAME_OFF;
	uint64_t launchOid  = base + DEVMODE_LAUNCH_OID_OFF;
	uint64_t launchName = base + DEVMODE_LAUNCH_NAME_OFF;

	// Sanity-check the offsets before writing: each OID's name pointer must still
	// be one of the two known strings. If not, the kernel layout differs -> skip
	// rather than corrupt the sysctl tree.
	uint64_t curDevName    = kread64(devOid + 48);
	uint64_t curLaunchName = kread64(launchOid + 48);
	oidswap_log("oidswap: cur dev=0x%llx launch=0x%llx | want dev=0x%llx launch=0x%llx\n",
	            (unsigned long long)curDevName, (unsigned long long)curLaunchName,
	            (unsigned long long)devName, (unsigned long long)launchName);
	if ((curDevName != devName && curDevName != launchName) ||
	    (curLaunchName != launchName && curLaunchName != devName)) {
		oidswap_log("oidswap: sanity FAILED, skipping\n");
		printf("devmode_oidswap: offsets stale (dev=0x%llx launch=0x%llx), skipping\n",
		       (unsigned long long)curDevName, (unsigned long long)curLaunchName);
		return -1;
	}

	if (hide) {
		kwrite64(devOid + 48, launchName);
		kwrite64(launchOid + 48, devName);
	} else {
		kwrite64(devOid + 48, devName);
		kwrite64(launchOid + 48, launchName);
	}
	oidswap_log("oidswap: applied hide=%d, devmode now=%d\n",
	            hide, probe_read_int("security.mac.amfi.developer_mode_status"));
	return 0;
}

int jbctl_handle_internal(const char *command, int argc, char* argv[])
{
	if (!strcmp(command, "launchd_stash_port")) {
		mach_port_t *selfInitPorts = NULL;
		mach_msg_type_number_t selfInitPortsCount = 0;
		if (mach_ports_lookup(mach_task_self(), &selfInitPorts, &selfInitPortsCount) != 0) {
			printf("ERROR: Failed port lookup on self\n");
			return -1;
		}
		if (selfInitPortsCount < 3) {
			printf("ERROR: Unexpected initports count on self\n");
			return -1;
		}
		if (selfInitPorts[2] == MACH_PORT_NULL) {
			printf("ERROR: Port to stash not set\n");
			return -1;
		}

		printf("Port to stash: %u\n", selfInitPorts[2]);

		mach_port_t launchdTaskPort;
		if (task_for_pid(mach_task_self(), 1, &launchdTaskPort) != 0) {
			printf("task_for_pid on launchd failed\n");
			return -1;
		}
		mach_port_t *launchdInitPorts = NULL;
		mach_msg_type_number_t launchdInitPortsCount = 0;
		if (mach_ports_lookup(launchdTaskPort, &launchdInitPorts, &launchdInitPortsCount) != 0) {
			printf("mach_ports_lookup on launchd failed\n");
			return -1;
		}
		if (launchdInitPortsCount < 3) {
			printf("ERROR: Unexpected initports count on launchd\n");
			return -1;
		}
		launchdInitPorts[2] = selfInitPorts[2]; // Transfer port to launchd
		if (mach_ports_register(launchdTaskPort, launchdInitPorts, launchdInitPortsCount) != 0) {
			printf("ERROR: Failed stashing port into launchd\n");
			return -1;
		}
		mach_port_deallocate(mach_task_self(), launchdTaskPort);
		return 0;
	}
	else if (!strcmp(command, "protection")) {
		bool toSet = false;
		if (argc > 1) {
			if (!strcmp(argv[1], "activate")) {
				toSet = true;
			}
			else if (!strcmp(argv[1], "deactivate")) {
				toSet = false;
			}
			else {
				return -1;
			}

			return protection_set_active(toSet);
		}
		return -1;
	}
	else if (!strcmp(command, "fakelib")) {
		bool toMount = false;
		if (argc > 1) {
			if (!strcmp(argv[1], "mount")) {
				toMount = true;
			}
			else if (!strcmp(argv[1], "unmount")) {
				toMount = false;
			}
			else {
				return -1;
			}

			return fakelib_set_mounted(toMount);
		}
		return -1;
	}
	else if (!strcmp(command, "devmode")) {
		bool toHide = false;
		bool validArg = false;
		if (argc > 1) {
			if (!strcmp(argv[1], "hide")) { toHide = true; validArg = true; }
			else if (!strcmp(argv[1], "show")) { toHide = false; validArg = true; }
		}
		if (!validArg) return -1;

		// Kept as an alias of "devmode_oidswap" for backwards compatibility.
		// It deliberately no longer calls developer_mode_set_hidden(): that wrote
		// the developer_mode_enabled storage to 0 for real, so any hide whose
		// matching "show" never ran left the device with developer mode actually
		// disabled. The oid swap only changes what the sysctl *reports*.
		if (jbclient_initialize_primitives() != 0) {
			printf("ERROR: failed to initialize krw primitives\n");
			return -1;
		}
		oidswap_log("devmode: alias -> oidswap hide=%d\n", toHide);
		return devmode_oidswap(toHide);
	}
	else if (!strcmp(command, "urlschemes")) {
		if (argc > 1) {
			if (!strcmp(argv[1], "hide")) return hide_global_urlschemes_hide();
			else if (!strcmp(argv[1], "show")) return hide_global_urlschemes_show();
		}
		return -1;
	}
	else if (!strcmp(command, "audit")) {
		if (argc > 1) {
			if (!strcmp(argv[1], "hide")) return hide_global_audit_hide();
			else if (!strcmp(argv[1], "restore")) return hide_global_audit_restore();
		}
		return -1;
	}
	else if (!strcmp(command, "mount")) {
		if (argc > 1) {
			return fakePath_mount(true, argv[1]);
		}
		return -1;
	}
	else if (!strcmp(command, "unmount")) {
		if (argc > 1) {
			return fakePath_mount(false, argv[1]);
		}
		return -1;
	}
	else if (!strcmp(command, "startup")) {
		protection_set_active(true);
		char *panicMessage = NULL;
		if (jbclient_watchdog_get_last_userspace_panic(&panicMessage) == 0) {
			NSString *printMessage = [NSString stringWithFormat:@"Dopamine has protected you from a userspace panic by temporarily disabling tweak injection and triggering a userspace reboot instead. A log is available under Analytics in the Preferences app. You can reenable tweak injection in the Dopamine app.\n\nPanic message: \n%s", panicMessage];
			CFUserNotificationDisplayAlert(0, 2/*kCFUserNotificationCautionAlertLevel*/, NULL, NULL, NULL, CFSTR("Watchdog Timeout"), (__bridge CFStringRef)printMessage, NULL, NULL, NULL, NULL);
			free(panicMessage);
		}
		exec_cmd(JBROOT_PATH("/usr/bin/uicache"), "-a", NULL);
	}
	else if (!strcmp(command, "install_pkg")) {
		if (argc > 1) {
			extern char **environ;
			const char *dpkg = JBROOT_PATH("/usr/bin/dpkg");
			int r = execve(dpkg, (char *const *)(const char *[]){dpkg, "-i", argv[1], NULL}, environ);
			return r;
		}
		return -1;
	}
	else if (!strcmp(command, "probe_sysctl")) {
		if (jbclient_initialize_primitives() != 0) {
			printf("ERROR: failed to initialize krw primitives\n");
			return -1;
		}
		probe_sysctl_oids();
		return 0;
	}
	else if (!strcmp(command, "devmode_oidswap")) {
		if (jbclient_initialize_primitives() != 0) {
			oidswap_log("oidswap: krw init FAILED\n");
			printf("ERROR: failed to initialize krw primitives\n");
			return -1;
		}
		bool hide = (argc > 1 && !strcmp(argv[1], "on"));
		oidswap_log("oidswap: cmd argc=%d argv1=%s -> hide=%d\n", argc,
		            (argc > 1 && argv[1]) ? argv[1] : "(none)", hide);
		return devmode_oidswap(hide);
	}
	return -1;
}
