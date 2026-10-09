// app_hide.m — RootHide-style jailbreak-level process hiding for "Hide for App".
//
// Ported from RootHide's libjailbreak/src/roothider/xpc_hook.m + blacklist.cpp.
// launchd hooks xpc_dictionary_create_reply / xpc_pipe_routine_reply and, for any
// request coming from a "hidden" (blacklisted) app, strips jailbreak coalitions
// out of the reply so the app cannot enumerate them.
//
// This runs entirely inside launchd — no app binary is modified. It complements
// the in-process hidejb hooks (which hide /var/jb etc. inside the injected app).

#import <Foundation/Foundation.h>

#include <libproc.h>
#include <sys/proc_info.h>
#include <mach/mach.h>
#include <mach/task_policy.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <pthread.h>
#include <xpc/xpc.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <litehook.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <sys/mount.h>

#include <libjailbreak/libjailbreak.h>
#include <xpc_private.h>
#include <libjailbreak/codesign.h>
#include <libjailbreak/util.h>
#include "jbserver/jbserver_local.h"

extern void systemwide_domain_set_enabled(bool enabled);

// Not exposed by the public SDK; same value RootHide uses in common.m.
#define PROC_PIDUNIQIDENTIFIERINFO 17

// string_has_prefix is defined in systemhook/src/common/common.c, which is
// compiled into launchdhook as well.
bool string_has_prefix(const char *str, const char *prefix);

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

static int proc_get_pidversion(pid_t pid)
{
	struct {
		uint8_t  p_uuid[16];
		uint64_t p_uniqueid;
		uint64_t p_puniqueid;
		int32_t  p_idversion;
		uint32_t p_reserve2;
		uint64_t p_reserve3;
		uint64_t p_reserve4;
	} uniqidinfo = {0};
	if (proc_pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO, 0, &uniqidinfo, sizeof(uniqidinfo)) <= 0) return 0;
	return uniqidinfo.p_idversion;
}

static bool proc_get_identifier(pid_t pid, char *out, size_t outSize)
{
	struct { uint32_t magic; uint32_t length; } header = {0};
	if (csops(pid, CS_OPS_IDENTITY, &header, sizeof(header)) != 0 && errno != ERANGE) return false;
	uint32_t len = ntohl(header.length);
	if (len == 0 || len > 4096) return false;
	char *buf = malloc(len);
	if (!buf) return false;
	bool ok = (csops(pid, CS_OPS_IDENTITY, buf, len) == 0);
	if (ok) strlcpy(out, buf + sizeof(header), outSize);
	free(buf);
	return ok;
}

// Simplified App Store detection: Apple system identifiers are "safe" (never
// hidden). RootHide additionally whitelists every installed App Store app via
// StoredAppIdentifiers; that is a follow-up. For now this means a hidden app also
// loses sight of other third-party coalitions, which is the safer direction for a
// detection-focused app.
static bool is_safe_bundle_identifier(const char *identifier)
{
	if (!identifier || !identifier[0]) return false;
	if (string_has_prefix(identifier, "com.apple.")) return true;
	return false;
}

// ---------------------------------------------------------------------------
// blacklisted (hidden) process tracking
// ---------------------------------------------------------------------------

static NSMutableDictionary<NSNumber *, NSNumber *> *gBlacklistedState = nil; // pid -> pidversion
static pthread_rwlock_t gStateLock = PTHREAD_RWLOCK_INITIALIZER;

static void state_init(void)
{
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		gBlacklistedState = [NSMutableDictionary dictionary];
	});
}

static bool is_blacklisted_token(audit_token_t *token)
{
	pid_t pid = audit_token_to_pid(*token);
	if (pid <= 0) return false;
	state_init();

	__block bool blacklisted = false;
	pthread_rwlock_rdlock(&gStateLock);
	NSNumber *cachedVersion = gBlacklistedState[@(pid)];
	if (cachedVersion && cachedVersion.intValue == proc_get_pidversion(pid)) {
		blacklisted = true;
	}
	pthread_rwlock_unlock(&gStateLock);
	return blacklisted;
}

void *app_hide_alloc_pid(void)
{
	pid_t *pidp = (pid_t *)malloc(sizeof(pid_t));
	*pidp = 0;
	return pidp;
}

static void app_hide_log(NSString *msg);

void app_hide_commit_pid(void *pidp)
{
	if (!pidp) return;
	pid_t pid = *(pid_t *)pidp;
	if (pid > 0) {
		state_init();
		int pidversion = proc_get_pidversion(pid);
		pthread_rwlock_wrlock(&gStateLock);
		gBlacklistedState[@(pid)] = @(pidversion);
		pthread_rwlock_unlock(&gStateLock);
		app_hide_log([NSString stringWithFormat:@"commit pid %d (version %d), blacklist size %lu", pid, pidversion, (unsigned long)gBlacklistedState.count]);

	}
	free(pidp);
}

bool app_hide_is_blacklisted_pid(pid_t pid)
{
	if (pid <= 0) return false;
	state_init();

	bool blacklisted = false;
	pthread_rwlock_rdlock(&gStateLock);
	NSNumber *cachedVersion = gBlacklistedState[@(pid)];
	if (cachedVersion && cachedVersion.intValue == proc_get_pidversion(pid)) {
		blacklisted = true;
	}
	pthread_rwlock_unlock(&gStateLock);
	return blacklisted;
}

// How many tracked no-inject pids are still alive (pid still has the same
// pidversion we recorded). Used to tell a real hide apart from a stale one.
static int app_hide_live_blacklisted_count(void)
{
	state_init();
	int live = 0;
	pthread_rwlock_rdlock(&gStateLock);
	for (NSNumber *pidNum in gBlacklistedState) {
		pid_t pid = (pid_t)pidNum.intValue;
		NSNumber *cachedVersion = gBlacklistedState[pidNum];
		if (cachedVersion.intValue == proc_get_pidversion(pid)) {
			live++;
		}
	}
	pthread_rwlock_unlock(&gStateLock);
	return live;
}

static void app_hide_remove_pid(pid_t pid)
{
	if (pid <= 0) return;
	state_init();
	pthread_rwlock_wrlock(&gStateLock);
	[gBlacklistedState removeObjectForKey:@(pid)];
	pthread_rwlock_unlock(&gStateLock);
}

// ---------------------------------------------------------------------------
// bind() hook (RootHide roothider.m new_bind) — force auto-assigned (port 0)
// sockets into the ephemeral range so jailbreak sockets don't land on a
// suspicious fixed port. Hooks launchd itself; applied via GOT rebind (no
// instruction replacement, which would panic launchd on arm64).
// ---------------------------------------------------------------------------

static int (*orig_bind)(int, const struct sockaddr *, socklen_t);

static int new_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (addr && addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
		struct sockaddr_in addr_in = *(struct sockaddr_in *)addr;
		in_port_t port = ntohs(addr_in.sin_port);
		if (port == 0) {
			int ret = -1;
			for (port = IPPORT_HIFIRSTAUTO; port <= IPPORT_HILASTAUTO; port++) {
				addr_in.sin_port = htons(port);
				ret = orig_bind(sockfd, (struct sockaddr *)&addr_in, addrlen);
				if (ret == 0 || errno != EADDRINUSE) break;
			}
			return ret;
		}
	}
	else if (addr && addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 addr_in6 = *(struct sockaddr_in6 *)addr;
		in_port_t port = ntohs(addr_in6.sin6_port);
		if (port == 0) {
			int ret = -1;
			for (port = IPPORT_HIFIRSTAUTO; port <= IPPORT_HILASTAUTO; port++) {
				addr_in6.sin6_port = htons(port);
				ret = orig_bind(sockfd, (struct sockaddr *)&addr_in6, addrlen);
				if (ret == 0 || errno != EADDRINUSE) break;
			}
			return ret;
		}
	}
	return orig_bind(sockfd, addr, addrlen);
}

static void app_hide_log(NSString *msg)
{
	FILE *f = fopen("/var/mobile/Documents/noinject_log.txt", "a");
	if (f) {
		fprintf(f, "%s\n", msg.UTF8String);
		fclose(f);
	}
}

// ---------------------------------------------------------------------------
// XPC reply hooks (RootHide xpc_hook.m)
// ---------------------------------------------------------------------------

static xpc_object_t (*orig_xpc_dictionary_create_reply)(xpc_object_t original);
static int (*orig_xpc_pipe_routine_reply)(xpc_object_t reply);

static xpc_object_t new_xpc_dictionary_create_reply(xpc_object_t original)
{
	xpc_object_t reply = orig_xpc_dictionary_create_reply(original);
	if (reply) {
		audit_token_t clientToken = {0};
		xpc_dictionary_get_audit_token(original, &clientToken);
		if (is_blacklisted_token(&clientToken)) {
			xpc_dictionary_set_value(reply, "roothide-blacklisted-process-request", original);
		}
	}
	return reply;
}

static int new_xpc_pipe_routine_reply(xpc_object_t reply)
{
	if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
		xpc_object_t original = xpc_dictionary_get_value(reply, "roothide-blacklisted-process-request");
		if (original) {
			xpc_dictionary_set_value(reply, "roothide-blacklisted-process-request", NULL);

			audit_token_t clientToken = {0};
			xpc_dictionary_get_audit_token(original, &clientToken);

			uint64_t routine = xpc_dictionary_get_uint64(original, "routine");
			uint64_t subsystem = xpc_dictionary_get_uint64(original, "subsystem");

			if (subsystem == 3 && routine == 829) {
				// coalition query: hide the coalition unless it is the app itself
				// or an Apple/App Store bundle.
				int64_t error = xpc_dictionary_get_int64(reply, "error");
				const char *name = xpc_dictionary_get_string(reply, "name");
				const char *bundle_identifier = xpc_dictionary_get_string(reply, "bundle_identifier");
				const char *bundle = bundle_identifier ? bundle_identifier : (name ? name : "");

				char client_identifier[255] = {0};
				proc_get_identifier(audit_token_to_pid(clientToken), client_identifier, sizeof(client_identifier));

				bool isSafe = is_safe_bundle_identifier(bundle);
				bool isSelf = client_identifier[0] && string_has_prefix(bundle, client_identifier);

				if (error == 0 && !isSelf && !isSafe) {
					xpc_dictionary_set_value(reply, "cid", NULL);
					xpc_dictionary_set_value(reply, "name", NULL);
					xpc_dictionary_set_value(reply, "bundle_identifier", NULL);
					xpc_dictionary_set_value(reply, "resource-usage-blob", NULL);
					xpc_dictionary_set_int64(reply, "error", 3);
				}
			}
		}
	}
	return orig_xpc_pipe_routine_reply(reply);
}

void app_hide_init(void)
{
	// Save the originals, then GOT-rebind (NOT instruction-replace). Instruction
	// replacement clears CS_VALID on arm64 and panics launchd (pid 1) during the
	// jailbreak "protection" stage; the existing initXPCHooks() uses GOT rebind for
	// exactly this reason.
	orig_xpc_dictionary_create_reply = (xpc_object_t (*)(xpc_object_t))xpc_dictionary_create_reply;
	orig_xpc_pipe_routine_reply = (int (*)(xpc_object_t))xpc_pipe_routine_reply;
	orig_bind = bind;
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)xpc_dictionary_create_reply, (void *)new_xpc_dictionary_create_reply, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)xpc_pipe_routine_reply, (void *)new_xpc_pipe_routine_reply, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, (void *)bind, (void *)new_bind, NULL);
}

// ---------------------------------------------------------------------------
// RootHide-style "no-injection" mode: temporary global hide + bare spawn
// ---------------------------------------------------------------------------

static bool gNoInjectActive = false;
static int gNoInjectRefCount = 0;
static pthread_mutex_t gNoInjectLock = PTHREAD_MUTEX_INITIALIZER;

// Set while a global hide is in effect and cleared by the matching restore.
// Lets the spawn hook detect a missed restore with a single flag read instead of
// stat-ing /var/jb on every process launch.
static bool gHideInFlight = false;
// When the current hide started. Guards the stale-hide check below against the
// short window where the flag is already set but the child pid has not been
// tracked yet.
static time_t gHideStartedAt = 0;

// Pids of jailbreak apps running "resurrected" (restored while the jailbreak was
// hidden). Killed before the jailbreak is re-hidden so they don't keep writing
// into the real jbroot after /var/jb is removed.
static NSMutableSet *gJailbreakAppPids = nil;
static pthread_mutex_t gJailbreakAppLock = PTHREAD_MUTEX_INITIALIZER;

static void app_hide_kill_jailbreak_apps(void);

static void app_hide_run_jbctl(const char *command, const char *arg)
{
	// jbctl carries the bindfs-allow entitlement + root; host a local jbserver so
	// it can talk to us, same pattern as ensure_fakelib_mounted().
	systemwide_domain_set_enabled(true);
	mach_port_t serverPort = jbserver_local_start();
	jbctl_earlyboot(serverPort, "internal", command, arg, NULL);
	jbserver_local_stop();
}

// Actual (reversible) hide/restore bodies, shared by the no-inject refcount
// path and the "jailbreak app resurrection" path.

static void app_hide_do_hide(void)
{
	// Kill running jailbreak apps first, so they don't keep writing into the
	// real jbroot after /var/jb is removed below.
	app_hide_kill_jailbreak_apps();

	// Unmount fakelib FIRST so the re-entrant jbctl spawn below runs without
	// systemhook injection (same proven pattern as ensure_fakelib_mounted()).
	unmount("/usr/lib", MNT_FORCE);

	// Quarantine the jailbreak files a bare app can still see (the "suspicious
	// files" under /var/mobile/Library). Pure file-rename, no uicache.
	app_hide_run_jbctl("audit", "hide");

	// Hide developer mode WITHOUT touching the real state (RootHide-style OID
	// swap): a bare app querying security.mac.amfi.developer_mode_status then
	// gets 0, while the real developer-mode storage stays untouched so the
	// jailbreak and developer-signed apps keep working. Undone in do_restore.
	// Developer-mode hiding is DISABLED on the per-app path on purpose. The swap
	// makes sysctlbyname("security.mac.amfi.developer_mode_status") report 0 for
	// EVERY process, and Dopamine itself is signed with get-task-allow: iOS then
	// answered with "Developer Mode Required" the moment the app was opened while
	// a hidden app was still alive, before any spawn hook could undo the swap.
	// Its offsets are also hardcoded for one device/iOS pair, so on every other
	// build it silently skipped anyway. (Manual "Hide Jailbreak" in the app UI
	// still does its own swap.)
	// app_hide_run_jbctl("devmode_oidswap", "on");

	// Remove the /var/jb symlink last.
	unlink("/var/jb");

	// A hide is now in flight; the spawn hook / watchdog repair it if the
	// matching restore is ever missed.
	gHideInFlight = true;
	gHideStartedAt = time(NULL);
}

// Rebuild the app registrations after /var/jb comes back.
//
// Hiding the jailbreak runs "uicache -u" on every bundle under /var/jb/Applications
// (DOEnvironmentManager -unregisterJailbreakApps), which REMOVES Sileo and the
// other jailbreak apps from the app database. Relinking /var/jb afterwards brings
// the files back but not the registrations, so the jailbreak store stayed missing
// from the home screen even though the jailbreak itself was healthy again.
//
// Retried, because the callers that matter here run during early boot, before lsd
// and installd are ready to accept a registration.
void app_hide_schedule_uicache(void)
{
	for (int attempt = 0; attempt < 4; attempt++) {
		int64_t delaySeconds = 5 + (int64_t)attempt * 15;
		dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delaySeconds * NSEC_PER_SEC),
			dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
				exec_cmd("/var/jb/usr/bin/uicache", "-a", NULL);
			});
	}
}

static void app_hide_do_restore(void)
{
	const char *jbroot = gSystemInfo.jailbreakInfo.rootPath;
	if (jbroot && jbroot[0]) {
		unlink("/var/jb");
		symlink(jbroot, "/var/jb");
	}

	// Swap developer-mode reporting back (the real storage was never touched).
	// per-app path never touches dev-mode (see app_hide_do_hide)
	// app_hide_run_jbctl("devmode_oidswap", "off");

	// Restore the quarantined files, then remount fakelib.
	app_hide_run_jbctl("audit", "restore");
	app_hide_run_jbctl("fakelib", "mount");

	// Rebuild the icon cache from HERE - launchd, root, unsandboxed - and only
	// after fakelib is back. The global hide unlinks /var/jb, and the jailbreak
	// apps (Sileo, Zebra, ...) live under /var/jb/Applications, so while it was
	// gone SpringBoard fell back to white placeholder icons and kept them until a
	// userspace reboot. Doing this from the jbctl audit-restore call did not take:
	// that context is sandboxed and it ran before fakelib was remounted. Delay a
	// little so the restore above is fully settled first.
	app_hide_schedule_uicache();

	gHideInFlight = false;
	gHideStartedAt = 0;
}

// Restore the jailbreak after a userspace reboot that happened while a no-inject
// app was running. In that case the launchd-side restore (watch_exit ->
// app_hide_global_restore) never fired because launchd itself was killed, leaving
// the quarantine in place and /var/jb unlinked. Returns true if a leftover
// transient hide was restored; false if the jailbreak is manually hidden and must
// stay hidden.
bool app_hide_restore_after_userspace_reboot(void)
{
	// Relink /var/jb and undo the hide. Whether the device should be hidden at all
	// is the caller's decision (main.m): a .safe_mode the user did not ask for - an
	// intercepted userspace panic, or a leftover from an older build - must not keep
	// the jailbreak hidden, because that removes /var/jb and leaves Sileo unable to
	// launch with every tweak pane missing from Settings.
	const char *jbroot = gSystemInfo.jailbreakInfo.rootPath;
	if (!jbroot || !jbroot[0]) return false;

	// Transient hide leftover. fakelib was already re-mounted by
	// ensure_fakelib_mounted() during the reboot, so only relink /var/jb and
	// restore the quarantined files.
	NSFileManager *fm = [NSFileManager defaultManager];
	NSString *jbRootPath = [NSString stringWithUTF8String:jbroot];
	[fm removeItemAtPath:@"/var/jb" error:nil];
	[fm createSymbolicLinkAtPath:@"/var/jb" withDestinationPath:jbRootPath error:nil];

	// A userspace reboot does not reset kernel memory, so a swap performed before
	// the reboot is still in effect -> undo it here.
	// per-app path never touches dev-mode (see app_hide_do_hide)
	// app_hide_run_jbctl("devmode_oidswap", "off");
	app_hide_run_jbctl("audit", "restore");
	app_hide_schedule_uicache();
	return true;
}

// Forward declaration: defined later in this file, but referenced above.
bool app_hide_is_currently_hidden(void);

// Repair a "half hidden" device: /var/jb missing while nothing is actually
// hidden and no manual hide is active. Returns true if it repaired something.
static bool app_hide_repair_half_hidden(void)
{
	const char *jbroot = gSystemInfo.jailbreakInfo.rootPath;
	if (!jbroot || !jbroot[0]) return false;

	NSString *jbRootStr = [NSString stringWithUTF8String:jbroot];

	// Jailbreak must be fully established, otherwise /var/jb is legitimately
	// absent for a moment during bootstrap and we must not race it.
	NSString *versionPath = [jbRootStr stringByAppendingPathComponent:@"basebin/.version"];
	if (![[NSFileManager defaultManager] fileExistsAtPath:versionPath]) return false;

	// Manual "Hide Jailbreak" is on -> leave it alone. A .safe_mode the user did not
	// ask for (watchdog panic recovery, or a leftover from an older build) must NOT
	// block the repair: blocking on it is what left /var/jb gone, Sileo unable to
	// launch and no visible tweak settings until the hide switch was cycled by hand.
	NSFileManager *repairFileManager = [NSFileManager defaultManager];
	NSString *safeModePath = [jbRootStr stringByAppendingPathComponent:@"basebin/.safe_mode"];
	NSString *userSafeModePath = [jbRootStr stringByAppendingPathComponent:@"basebin/.safe_mode_user"];
	if ([repairFileManager fileExistsAtPath:safeModePath] && [repairFileManager fileExistsAtPath:userSafeModePath]) return false;

	// Stale-hide detection -- the fix for "I have to tap Hide Jailbreak every so
	// often". app_hide_is_currently_hidden() is pure bookkeeping: when a
	// no-inject app dies without its watch_exit firing (killed while launchd was
	// busy, pidversion churn) the flag stays set forever, and every repair path
	// used to bail out on it -- leaving the device hidden with no way back except
	// the manual toggle. If the flag is set but not one tracked no-inject app is
	// still alive, the hide is stale: clear it and carry on to the repair below.
	if (app_hide_is_currently_hidden()) {
		// Staleness is judged from the tracked pid list. The refcount must NOT be part
		// of this test: it is only lowered by app_hide_global_restore, so if a restore
		// is ever missed it stays above zero forever and a refcount-gated test could
		// never clear it - which left /var/jb removed, the store gone and no way back
		// except cycling the Hide Jailbreak switch. Clearing a stale hide resets the
		// refcount together with the flag, so recovery still works.
		bool stale = (gHideStartedAt != 0) &&
		             (time(NULL) - gHideStartedAt >= 15) &&
		             (app_hide_live_blacklisted_count() == 0);
		if (!stale) {
			// Hidden on purpose (a tracked no-inject app is alive, or the hide
			// has only just started).
			return false;
		}
		app_hide_log(@"selfheal: hide flagged but no tracked no-inject app alive -> stale hide, clearing");
		pthread_mutex_lock(&gNoInjectLock);
		gNoInjectRefCount = 0;
		gNoInjectActive = false;
		pthread_mutex_unlock(&gNoInjectLock);
		gHideStartedAt = 0;
	}

	// /var/jb present: nothing to fix.
	if (access("/var/jb", F_OK) == 0) {
		// Except for a .safe_mode nobody asked for. The watchdog writes it when it
		// intercepts a userspace panic, and tweak injection is keyed off it, so every
		// process launched afterwards loads no tweaks and the tweak pages in Settings
		// stay empty - the other half of the damage the /var/jb repair above handles.
		// /var/jb exists here, so this cannot be a hide in progress; a real choice
		// always carries its own marker.
		NSString *straySafeMode = [jbRootStr stringByAppendingPathComponent:@"basebin/.safe_mode"];
		NSString *strayAutoMark = [jbRootStr stringByAppendingPathComponent:@"basebin/.safe_mode_auto"];
		NSString *userHideMark = [jbRootStr stringByAppendingPathComponent:@"basebin/.safe_mode_user"];
		NSString *injectOffMark = [jbRootStr stringByAppendingPathComponent:@"basebin/.safe_mode_inject_off"];
		NSFileManager *selfhealFM = [NSFileManager defaultManager];
		if ([selfhealFM fileExistsAtPath:straySafeMode] &&
		    ![selfhealFM fileExistsAtPath:userHideMark] &&
		    ![selfhealFM fileExistsAtPath:injectOffMark]) {
			app_hide_log(@"selfheal: stray .safe_mode while visible -> clearing so tweaks inject again");
			[selfhealFM removeItemAtPath:straySafeMode error:nil];
			[selfhealFM removeItemAtPath:strayAutoMark error:nil];
		}
		gHideInFlight = false;
		gHideStartedAt = 0;
		return false;
	}

	app_hide_log(@"selfheal: /var/jb missing while not hidden -> relinking");
	NSFileManager *fm = [NSFileManager defaultManager];
	[fm removeItemAtPath:@"/var/jb" error:nil];
	[fm createSymbolicLinkAtPath:@"/var/jb" withDestinationPath:jbRootStr error:nil];
	// per-app path never touches dev-mode (see app_hide_do_hide)
	// app_hide_run_jbctl("devmode_oidswap", "off");
	app_hide_run_jbctl("audit", "restore");
	app_hide_run_jbctl("fakelib", "mount");
	app_hide_schedule_uicache();
	gHideInFlight = false;
	gHideStartedAt = 0;
	return true;
}

// Very cheap fast path called from the launchd spawn hook on EVERY spawn: a
// single bool read in the normal case. Only when a hide happened and its restore
// was missed does it do any real work, repairing the device within one spawn.
void app_hide_maybe_heal(void)
{
	if (!gHideInFlight) return;
	app_hide_repair_half_hidden();
}

// Slow safety net (see app_hide.h): catches the case where launchd itself
// restarted and lost gHideInFlight, so the spawn-hook fast path can no longer
// tell that a hide is outstanding.
void app_hide_start_selfheal(void)
{
	dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
		dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
	dispatch_source_set_timer(timer,
		dispatch_time(DISPATCH_TIME_NOW, 10ull * NSEC_PER_SEC),
		10ull * NSEC_PER_SEC, 5ull * NSEC_PER_SEC);
	dispatch_source_set_event_handler(timer, ^{
		app_hide_repair_half_hidden();
	});
	dispatch_resume(timer);
}

void app_hide_global_hide(void)
{
	// Reference-counted: multiple no-inject apps may run concurrently. The
	// actual hide only runs when the jailbreak isn't already hidden (i.e. the
	// first no-inject app, or the first after a jailbreak-app resurrection).
	pthread_mutex_lock(&gNoInjectLock);
	gNoInjectRefCount++;
	int refcount = gNoInjectRefCount;
	bool wasHidden = gNoInjectActive;
	gNoInjectActive = true;
	pthread_mutex_unlock(&gNoInjectLock);
	app_hide_log([NSString stringWithFormat:@"global_hide: refcount now %d", refcount]);
	if (wasHidden) return;

	app_hide_do_hide();
}

void app_hide_global_restore(void)
{
	// Only restore once the LAST hidden app has exited.
	pthread_mutex_lock(&gNoInjectLock);
	if (gNoInjectRefCount <= 0) {
		pthread_mutex_unlock(&gNoInjectLock);
		app_hide_log(@"global_restore: refcount already 0 (no-op)");
		return;
	}
	gNoInjectRefCount--;
	int refcount = gNoInjectRefCount;
	if (refcount > 0) {
		pthread_mutex_unlock(&gNoInjectLock);
		app_hide_log([NSString stringWithFormat:@"global_restore: refcount now %d (skip, still hidden)", refcount]);
		return;
	}
	gNoInjectActive = false;
	pthread_mutex_unlock(&gNoInjectLock);
	app_hide_log(@"global_restore: refcount 0, restoring jailbreak");

	app_hide_do_restore();
}

bool app_hide_is_currently_hidden(void)
{
	pthread_mutex_lock(&gNoInjectLock);
	bool hidden = gNoInjectActive;
	pthread_mutex_unlock(&gNoInjectLock);
	return hidden;
}

bool app_hide_is_jailbreak_app(const char *path)
{
	// A "jailbreak app" is an app bundle (contains ".app/") installed inside
	// the jailbreak root itself (Sileo, Filza, Terminal, ...). It may be
	// launched via the /var/jb/ symlink OR via the fully-resolved preboot path,
	// so accept both. Requiring ".app/" also excludes jailbreak binaries like
	// jbctl (spawned re-entrantly during hide/restore) from a false resurrect.
	if (!path) return false;
	if (!strstr(path, ".app/")) return false;
	if (strncmp(path, "/var/jb/", 8) == 0) return true;
	const char *jbroot = gSystemInfo.jailbreakInfo.rootPath;
	if (jbroot && jbroot[0]) {
		size_t len = strlen(jbroot);
		if (len > 0 && strncmp(path, jbroot, len) == 0) return true;
	}
	return false;
}

// Read an app bundle's CFBundleIdentifier from its launch path (.../X.app/X).
static NSString *app_hide_bundle_id(const char *path)
{
	if (!path) return nil;
	NSString *result = nil;
	@autoreleasepool {
		NSString *p = [NSString stringWithUTF8String:path];
		NSRange r = [p rangeOfString:@".app/"];
		if (r.location != NSNotFound) {
			NSString *appPath = [p substringToIndex:r.location + 4];
			NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
			                      [appPath stringByAppendingPathComponent:@"Info.plist"]];
			id bundleID = info[@"CFBundleIdentifier"];
			if ([bundleID isKindOfClass:[NSString class]]) result = [bundleID copy];
		}
	}
	return result;
}

// The Dopamine app itself is TrollStore-installed under /var/containers/Bundle/
// Application, i.e. NOT under the jailbreak root, so app_hide_is_jailbreak_app()
// does not match it. It must still resurrect: while hidden the dev-mode OID swap
// makes security.mac.amfi.developer_mode_status report 0, and Dopamine requires
// developer mode, so iOS prompted "Enable Developer Mode" on every open.
bool app_hide_is_dopamine_app(const char *path)
{
    if (!path) return false;
    if (!strstr(path, ".app/")) return false;
    static NSString *dopamineBundleID = @"com.opa334.Dopamine";
    return [app_hide_bundle_id(path) isEqualToString:dopamineBundleID];
}

// The Settings app (Preferences.app, stock path /Applications/Preferences.app)
// is effectively a jailbreak app: it is where every tweak's settings bundle is
// listed from (/var/jb/Library/PreferenceBundles + PreferencePanes). While the
// jailbreak is globally hidden it shows NO tweak settings at all, so it has to
// resurrect the jailbreak exactly like Sileo does.
bool app_hide_is_settings_app(const char *path)
{
	if (!path) return false;
	if (!strstr(path, ".app/")) return false;
	// Path-based fallback, in case Info.plist can't be read.
	if (strstr(path, "/Applications/Preferences.app/") != NULL) return true;
	static NSString *settingsBundleID = @"com.apple.Preferences";
	return [app_hide_bundle_id(path) isEqualToString:settingsBundleID];
}

void app_hide_resurrect_for_jb_app(void)
{
	// "Jailbreak app resurrection": a jailbreak app was spawned while the
	// jailbreak was hidden (a no-inject app is running). Restore the jailbreak
	// so the jailbreak app can run. The no-inject refcount is left intact (those
	// apps are still running); only the hidden state is cleared, and we do NOT
	// re-hide later (accepted limitation).
	pthread_mutex_lock(&gNoInjectLock);
	bool wasHidden = gNoInjectActive;
	gNoInjectActive = false;
	pthread_mutex_unlock(&gNoInjectLock);
	if (!wasHidden) return;
	app_hide_log(@"resurrect: jailbreak app spawned while hidden, restoring jailbreak");
	app_hide_do_restore();
}

void app_hide_track_jailbreak_app(pid_t pid)
{
	if (pid <= 0) return;
	pthread_mutex_lock(&gJailbreakAppLock);
	if (!gJailbreakAppPids) gJailbreakAppPids = [NSMutableSet set];
	[gJailbreakAppPids addObject:@(pid)];
	pthread_mutex_unlock(&gJailbreakAppLock);
}

// Kill the "resurrected" apps by scanning the process table, so this does not
// depend on transient pid bookkeeping (pids get reused, and the tracked list is
// cleared on every re-hide, which used to leave a still-running app behind).
//
// Two things must die before /var/jb disappears:
//   1. jailbreak apps (Sileo, Filza, ...): they keep writing into the real
//      jbroot once /var/jb is gone, which is a real corruption risk;
//   2. Settings.app: it caches the (empty) tweak list it read while the jailbreak
//      was hidden, so without a kill it would come back with no tweak settings.
//
// Matching is by real executable path via proc_pidpath(): jailbreak apps live
// under <jbroot>/Applications/*.app, Settings at /Applications/Preferences.app.
// Helper processes (PreferencesAgent, ...) live inside a .app but are not the app
// executable itself — however killing them with the app is harmless and matches
// what the user asked for, so anything whose path is inside a matching .app goes.
static BOOL app_hide_path_is_resurrected_app(const char *path)
{
	if (!path) return NO;
	if (app_hide_is_settings_app(path)) return YES;
	if (!strstr(path, ".app/")) return NO;

	// Any app running from the jailbreak root's Applications folder.
	const char *jbroot = gSystemInfo.jailbreakInfo.rootPath;
	if (jbroot && jbroot[0]) {
		size_t len = strlen(jbroot);
		if (len > 0 && strncmp(path, jbroot, len) == 0 && strstr(path, "/Applications/")) {
			return YES;
		}
	}
	if (strncmp(path, "/var/jb/", 8) == 0 && strstr(path, "/Applications/")) {
		return YES;
	}
	return NO;
}

static void app_hide_kill_resurrected_apps(void)
{
	int byteCount = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
	if (byteCount <= 0) return;

	pid_t *pids = malloc((size_t)byteCount);
	if (!pids) return;
	byteCount = proc_listpids(PROC_ALL_PIDS, 0, pids, byteCount);
	if (byteCount <= 0) {
		free(pids);
		return;
	}

	int n = byteCount / (int)sizeof(pid_t);
	for (int i = 0; i < n; i++) {
		pid_t pid = pids[i];
		if (pid <= 1) continue; // never touch launchd

		char path[4 * MAXPATHLEN] = {0};
		if (proc_pidpath(pid, path, sizeof(path)) <= 0) continue;
		if (!app_hide_path_is_resurrected_app(path)) continue;

		if (kill(pid, SIGKILL) == 0) {
			app_hide_log([NSString stringWithFormat:@"kill resurrected app pid %d (%s)", pid, path]);
		}
	}
	free(pids);
}

static void app_hide_kill_jailbreak_apps(void)
{
	app_hide_kill_resurrected_apps();

	pthread_mutex_lock(&gJailbreakAppLock);
	NSArray *pids = [gJailbreakAppPids allObjects];
	[gJailbreakAppPids removeAllObjects];
	pthread_mutex_unlock(&gJailbreakAppLock);
	for (NSNumber *pidNum in pids) {
		pid_t pid = pidNum.intValue;
		if (pid > 0 && kill(pid, SIGKILL) == 0) {
			app_hide_log([NSString stringWithFormat:@"kill jailbreak app pid %d", pid]);
		}
	}
}

// Query a pid's app state (proc_pidinfo flavor 22 = PROC_PIDT_APPSTATE), a
// direct foreground/background signal that does NOT need the task port (unlike
// task_policy_get, which needs task_for_pid and is denied from launchd).
// Returns the raw app state, or -1 if it can't be queried.
static int app_hide_get_app_state(pid_t pid)
{
	// Preferred source: struct proc_pidappstateinfo is just { uint32_t app_state; }.
	uint32_t app_state = 0;
	if (proc_pidinfo(pid, 22 /* PROC_PIDT_APPSTATE */, 0, &app_state, sizeof(app_state)) == (int)sizeof(app_state)) {
		return (int)app_state;
	}

	// Fallback: on some builds PROC_PIDT_APPSTATE returns nothing at all (seen on
	// device as app_state=-1), which used to make the background detection a
	// no-op and left the jailbreak hidden after the app was merely backgrounded.
	// A suspended process (SSTOP) is by definition the backgrounded case, so use
	// the BSD info status instead.
	struct proc_bsdinfo bsd = {0};
	if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd)) == (int)sizeof(bsd)) {
		if (bsd.pbi_status == 4 /* SSTOP: suspended */) return 3; // background
		return 1;                                                 // running/sleeping => foreground
	}
	return -1;
}

void app_hide_check_role_after_spawn(pid_t pid)
{
	if (pid <= 0) return;

	// Poll instead of doing a single check: the global hide must last exactly as
	// long as the hidden app is in the FOREGROUND. The old one-shot 500ms check
	// only caught a background *launch*; when the app was backgrounded later
	// (user returns to the home screen or opens another app) the jailbreak stayed
	// hidden, so Sileo would not open and Settings showed no tweak entries until
	// the app was force-quit. First check at 500ms, then every 2s.
	// Counts consecutive polls that did not read as foreground.
	__block int notForegroundPolls = 0;
	dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
		dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
	dispatch_source_set_timer(timer,
		dispatch_time(DISPATCH_TIME_NOW, 500ull * NSEC_PER_MSEC),
		2ull * NSEC_PER_SEC, 500ull * NSEC_PER_MSEC);
	dispatch_source_set_event_handler(timer, ^{
		// App gone: app_hide_watch_exit owns the restore.
		if (!app_hide_is_blacklisted_pid(pid)) {
			dispatch_source_cancel(timer);
			return;
		}

		int appState = app_hide_get_app_state(pid);
		app_hide_log([NSString stringWithFormat:@"appstate_check: pid %d app_state=%d", pid, appState]);
		// Unknown: keep hiding. Being conservative here only risks staying hidden
		// (which the self-heal can repair), while restoring by mistake would expose
		// the jailbreak to the app we are hiding it from.
		if (appState < 0) return;

		// 1 = PROC_APPSTATE_ACTIVE (foreground).
		if (appState == 1) {
			notForegroundPolls = 0;
			return;
		}

		// One non-active reading is NOT a backgrounding. An app that is still on
		// screen reads as something other than ACTIVE during its launch, while a
		// system alert covers it, and during any transition - and restoring on the
		// first such reading brought the jailbreak back within a second or two of the
		// app opening, so the app detected it again. That is the "Hide for App does
		// not work" failure: the hide was real, it was simply undone immediately.
		// Only a state that stays non-foreground across several polls is a real
		// backgrounding; that still releases the hide, a few seconds later.
		notForegroundPolls++;
		if (notForegroundPolls < 3) {
			app_hide_log([NSString stringWithFormat:@"appstate_check: pid %d app_state=%d (poll %d), keeping hide", pid, appState, notForegroundPolls]);
			return;
		}

		app_hide_log([NSString stringWithFormat:@"appstate_check: pid %d not foreground for %d polls, restoring jailbreak", pid, notForegroundPolls]);
		app_hide_global_restore();
		dispatch_source_cancel(timer);
	});
	dispatch_resume(timer);
}

void app_hide_watch_exit(pid_t pid)
{
	if (pid <= 0) return;

	dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, (uintptr_t)pid, DISPATCH_PROC_EXIT,
		dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0));
	dispatch_source_set_event_handler(source, ^{
		app_hide_log([NSString stringWithFormat:@"watch_exit: pid %d exited", pid]);
		app_hide_remove_pid(pid);
		app_hide_global_restore();
		dispatch_source_cancel(source);
	});
	dispatch_resume(source);
}
