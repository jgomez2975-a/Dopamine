#ifndef JB_VISIBILITY_WATCHDOG_H
#define JB_VISIBILITY_WATCHDOG_H
#include "JBVisibilityState.h"

// State5-inspired reconciliation, but use our existing transition owner instead
// of a second blocking action lock. Live AND not-yet-spawned leases both count.
typedef struct { unsigned consecutiveFailures; } JBVisibilityWatchdog;
static inline int jb_visibility_reconcile_idle(JBVisibilityState *s,
    JBVisibilityWatchdog *watchdog, JBVisibilityOperation checkAndRestore,
    void *context, bool *attempted)
{
    if (attempted) *attempted = false;
    pthread_mutex_lock(&s->lock);
    if (s->busy || s->restartPrepared || s->references != 0) {
        pthread_mutex_unlock(&s->lock);
        return EBUSY;
    }
    // An explicit successful recovery rearms the watchdog. Repeated failures
    // do not cause endless helper spawning or overwrite the actual last error.
    if (s->phase == JB_VISIBLE) {
        watchdog->consecutiveFailures = 0;
        pthread_mutex_unlock(&s->lock);
        // Unlike State5, never guess that an externally absent /var/jb is ours
        // to repair: it may be an intentional manual-hide operation.
        return 0;
    }
    if (watchdog->consecutiveFailures >= 3) {
        pthread_mutex_unlock(&s->lock);
        return ECANCELED;
    }
    s->busy = true;
    if (attempted) *attempted = true;
    pthread_mutex_unlock(&s->lock);
    int result = checkAndRestore(context);
    pthread_mutex_lock(&s->lock);
    s->phase = result == 0 ? JB_VISIBLE : JB_VISIBILITY_FAILED;
    s->lastError = result;
    watchdog->consecutiveFailures = result == 0 ? 0 : watchdog->consecutiveFailures + 1;
    // No lease existed at reservation and acquisitions were blocked throughout.
    // A duplicate exit callback cannot request a second recovery here.
    s->restorePending = false;
    s->busy = false;
    pthread_mutex_unlock(&s->lock);
    return result;
}
#endif
