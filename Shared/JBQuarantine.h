#ifndef JB_QUARANTINE_H
#define JB_QUARANTINE_H
#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#ifndef JBQ_ROOT
#define JBQ_ROOT @"/var/mobile/.DopamineHideQuarantine"
#endif
#ifndef JBQ_RENAME
#define JBQ_RENAME renamex_np
#endif
#ifndef JBQ_WRITE_MAP
#define JBQ_WRITE_MAP(map, path) [(map) writeToFile:(path) atomically:YES]
#endif
#ifndef JBQ_LOG
static inline void auditDefaultLog(NSString *message) {
 FILE *file = fopen("/var/mobile/audit_log.txt", "a");
 if (file) { fprintf(file, "%s\n", message.UTF8String); fclose(file); }
}
#define JBQ_LOG(message) auditDefaultLog(message)
#endif
static inline NSString *hideQuarantineRoot(void) { return JBQ_ROOT; }
static inline NSString *hideMapPath(void) { return [hideQuarantineRoot() stringByAppendingPathComponent:@"map.plist"]; }
static inline NSString *auditLockPath(void) { return [hideQuarantineRoot() stringByAppendingPathComponent:@".transaction.lock"]; }
static inline void auditLog(NSString *message) { JBQ_LOG(message); }
static inline int auditPathState(NSString *path) {
 struct stat st;
 if (lstat(path.fileSystemRepresentation, &st) == 0) return 1;
 return errno == ENOENT ? 0 : -1;
}
// Never unlink this lock file: all cooperating processes must lock one inode.
// Nonblocking acquisition avoids deadlocking launchd via its synchronous helper.
static inline int auditWithLock(int (^operation)(void)) {
 NSFileManager *fm = [NSFileManager defaultManager];
 if (![fm createDirectoryAtPath:hideQuarantineRoot() withIntermediateDirectories:YES attributes:nil error:nil]) return EIO;
 struct stat root;
 if (lstat(hideQuarantineRoot().fileSystemRepresentation, &root) != 0 || !S_ISDIR(root.st_mode)) return EINVAL;
 int fd = open(auditLockPath().fileSystemRepresentation, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
 if (fd < 0) return errno;
 struct stat opened, named;
 if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode) || opened.st_nlink != 1) { close(fd); return EINVAL; }
 if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
  int result = errno == EWOULDBLOCK ? EBUSY : errno;
  close(fd); auditLog(@"audit_transaction_v2: busy/error; no journal changes"); return result;
 }
 int result;
 @try {
  if (lstat(auditLockPath().fileSystemRepresentation, &named) != 0 || named.st_dev != opened.st_dev || named.st_ino != opened.st_ino) result = ESTALE;
  else result = operation();
 } @finally { flock(fd, LOCK_UN); close(fd); }
 return result;
}
static inline int auditValidateMap(NSArray *map) {
	// Validate the entire journal before moving anything; do not discard malformed
	// entries or allow a destination outside the quarantine directory.
	for (id entry in map) {
		if (![entry isKindOfClass:[NSDictionary class]]) return EINVAL;
		id src = entry[@"src"], dst = entry[@"dst"];
		if (![src isKindOfClass:[NSString class]] || ![dst isKindOfClass:[NSString class]]) return EINVAL;
		if (![src isAbsolutePath] || ![dst isAbsolutePath] ||
		    ![src isEqualToString:[src stringByStandardizingPath]] ||
		    ![dst isEqualToString:[dst stringByStandardizingPath]] ||
		    ![[dst stringByDeletingLastPathComponent] isEqualToString:hideQuarantineRoot()] ||
		    [dst isEqualToString:hideMapPath()] || [dst isEqualToString:auditLockPath()] ||
		    [src isEqualToString:@"/"] || [src isEqualToString:hideQuarantineRoot()] ||
		    [src hasPrefix:[hideQuarantineRoot() stringByAppendingString:@"/"]]) return EINVAL;
	}

 return 0;
}
static inline int auditReadMap(NSMutableArray **outMap) {
 struct stat st;
 if (lstat(hideMapPath().fileSystemRepresentation, &st) != 0) {
  if (errno != ENOENT) return errno;
  *outMap = [NSMutableArray array]; return 0;
 }
 if (!S_ISREG(st.st_mode)) return EINVAL;
 NSArray *map = [NSArray arrayWithContentsOfFile:hideMapPath()];
 if (!map) { auditLog(@"audit_restore_v1: unreadable journal; preserved"); return EINVAL; }
 int result = auditValidateMap(map);
 if (result != 0) return result;
 *outMap = [map mutableCopy]; return 0;
}
// Caller holds auditWithLock across the WHOLE audit, not merely each item.
static inline int hideItemAtPath(NSString *src) {
 NSMutableArray *map = nil;
 int result = auditReadMap(&map);
 if (result != 0) return result;
 NSString *dst = [hideQuarantineRoot() stringByAppendingPathComponent:[NSUUID UUID].UUIDString];
 NSDictionary *entry = @{@"src":src,@"dst":dst};
 result = auditValidateMap(@[entry]);
 if (result != 0) return result;
 for (NSDictionary *existing in map) {
  if ([existing[@"src"] isEqualToString:src]) {
   // A previous complete hide is idempotent; never quarantine a new file
   // over an unresolved old copy of the same original path.
   if (auditPathState(src) == 0 && auditPathState(existing[@"dst"]) == 1) return 0;
   return EEXIST;
  }
 }
 if (auditPathState(src) != 1) return ENOENT;
 [map addObject:entry];
 // Write-ahead: on failure the original is never moved. If the process exits
 // after this point, restore handles both the unmoved and moved cases.
 if (!JBQ_WRITE_MAP(map, hideMapPath())) {
  auditLog(@"audit_transaction_v2: journal write failed; original untouched"); return EIO;
 }
 int journal = open(hideMapPath().fileSystemRepresentation, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
 if (journal < 0) return errno;
 result = fsync(journal) == 0 ? 0 : errno; close(journal);
 if (result != 0) return result;
 // Atomic, no-clobber move. Never fall back to copy/delete across volumes.
 if (JBQ_RENAME(src.fileSystemRepresentation, dst.fileSystemRepresentation, RENAME_EXCL) != 0) {
  result = errno; auditLog(@"audit_transaction_v2: move failed; journal retained"); return result;
 }
 if (auditPathState(src) != 0 || auditPathState(dst) != 1) return EIO;
 auditLog(@"audit_transaction_v2: journaled hide completed");
 return 0;
}
static inline int restoreHiddenItems(void)
{
	NSFileManager *fm = [NSFileManager defaultManager];
	NSMutableArray *map = nil;
	int readResult = auditReadMap(&map);
	if (readResult != 0) return readResult;
	if (auditPathState(hideMapPath()) == 0) return 0;
	int result = 0;
	for (NSDictionary *entry in [map reverseObjectEnumerator]) {
		NSString *src = entry[@"src"];
		NSString *dst = entry[@"dst"];
		int srcState = auditPathState(src), dstState = auditPathState(dst);
		if (srcState == 1 && dstState == 0) continue; // prior completed move
		if (srcState != 0 || dstState != 1) {
			result = (srcState == 1 && dstState == 1) ? EEXIST : EIO;
			auditLog([NSString stringWithFormat:@"audit_restore_v1: conflict/missing item; preserved: %@", src]);
			continue;
		}
		NSError *error = nil;
		if (![fm createDirectoryAtPath:[src stringByDeletingLastPathComponent]
	      withIntermediateDirectories:YES
	                       attributes:nil
	                            error:&error] ||
		    JBQ_RENAME(dst.fileSystemRepresentation, src.fileSystemRepresentation, RENAME_EXCL) != 0 ||
		    auditPathState(src) != 1 || auditPathState(dst) != 0) {
			result = EIO;
			auditLog([NSString stringWithFormat:@"audit_restore_v1: restore failed; journal retained: %@ (%@)", src, error]);
		}
	}
	if (result != 0) return result;
	NSError *error = nil;
	if (![fm removeItemAtPath:hideMapPath() error:&error]) {
		auditLog([NSString stringWithFormat:@"audit_restore_v1: journal cleanup failed: %@", error]);
		return EIO;
	}
	return 0;
}


#endif
