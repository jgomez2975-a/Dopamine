#ifndef JB_VISIBILITY_STATE_H
#define JB_VISIBILITY_STATE_H
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

/* One owner applies filesystem transitions. Never hold the state mutex while
 * calling an operation: jbctl synchronously re-enters launchd's spawn hook.
 * Contending acquisitions/restores return EBUSY, rather than blocking launchd.
 * A final lease release during an operation is drained by that operation's
 * owner before it publishes idle. No detached retries or unbounded loops.
 */
typedef enum { JB_VISIBLE, JB_HIDDEN, JB_VISIBILITY_FAILED } JBVisibilityPhase;
typedef struct { bool held; } JBVisibilityLease;
typedef int (*JBVisibilityOperation)(void *context);
typedef struct {
    pthread_mutex_t lock;
    JBVisibilityPhase phase;
    unsigned int references;
    bool busy;
    bool restorePending;
    bool restartPrepared;
    int lastError;
} JBVisibilityState;
#define JB_VISIBILITY_INITIALIZER { PTHREAD_MUTEX_INITIALIZER, JB_VISIBLE, 0, false, false, false, 0 }

static inline int jb_visibility_finish(JBVisibilityState *s,
    JBVisibilityPhase phase, int operationResult, int stateError,
    JBVisibilityOperation restore, void *context)
{
    pthread_mutex_lock(&s->lock);
    s->phase = phase;
    s->lastError = stateError;
    bool drain = s->restorePending && s->references == 0 && phase != JB_VISIBLE;
    s->restorePending = false;
    if (!drain) {
        s->busy = false;
        pthread_mutex_unlock(&s->lock);
        return operationResult;
    }
    pthread_mutex_unlock(&s->lock);
    int result = restore(context);
    pthread_mutex_lock(&s->lock);
    s->phase = result == 0 ? JB_VISIBLE : JB_VISIBILITY_FAILED;
    s->lastError = result;
    // No acquisition can succeed while busy, so another final release cannot
    // require a different transition here. A failure remains explicit/retryable.
    s->restorePending = false;
    s->busy = false;
    pthread_mutex_unlock(&s->lock);
    return operationResult != 0 ? operationResult : result;
}

static inline int jb_visibility_acquire(JBVisibilityState *s, JBVisibilityLease *lease,
    JBVisibilityOperation hide, JBVisibilityOperation restore, void *context)
{
    pthread_mutex_lock(&s->lock);
    if (s->busy || s->restartPrepared) { pthread_mutex_unlock(&s->lock); return EBUSY; }
    if (s->phase == JB_VISIBILITY_FAILED) {
        int error = s->lastError ? s->lastError : EIO;
        pthread_mutex_unlock(&s->lock); return error;
    }
    // Same owner cannot increment the count twice. If resurrected while it
    // still holds its lease, a repeated acquire is a no-op, not a second hide.
    if (lease->held) { pthread_mutex_unlock(&s->lock); return 0; }
    if (s->references == UINT_MAX) { pthread_mutex_unlock(&s->lock); return EOVERFLOW; }
    lease->held = true;
    s->references++;
    if (s->phase == JB_HIDDEN) { pthread_mutex_unlock(&s->lock); return 0; }
    s->busy = true;
    pthread_mutex_unlock(&s->lock);

    int result = hide(context);
    if (result != 0) {
        pthread_mutex_lock(&s->lock);
        if (lease->held) { lease->held = false; s->references--; }
        pthread_mutex_unlock(&s->lock);
        int rollback = restore(context);
        return jb_visibility_finish(s, rollback == 0 ? JB_VISIBLE : JB_VISIBILITY_FAILED,
            result, rollback, restore, context);
    }
    pthread_mutex_lock(&s->lock);
    bool canceled = !lease->held;
    pthread_mutex_unlock(&s->lock);
    return jb_visibility_finish(s, JB_HIDDEN, canceled ? ECANCELED : 0, 0, restore, context);
}

static inline int jb_visibility_release(JBVisibilityState *s, JBVisibilityLease *lease,
    JBVisibilityOperation restore, void *context)
{
    pthread_mutex_lock(&s->lock);
    if (lease->held) { lease->held = false; s->references--; }
    // Repeated callbacks cannot release another process's reference.
    if (s->references != 0) { pthread_mutex_unlock(&s->lock); return 0; }
    if (s->busy) {
        s->restorePending = true;
        pthread_mutex_unlock(&s->lock); return EBUSY;
    }
    if (s->phase == JB_VISIBLE) { pthread_mutex_unlock(&s->lock); return 0; }
    s->busy = true;
    pthread_mutex_unlock(&s->lock);
    int result = restore(context);
    return jb_visibility_finish(s, result == 0 ? JB_VISIBLE : JB_VISIBILITY_FAILED,
        result, result, restore, context);
}

static inline int jb_visibility_restore(JBVisibilityState *s,
    JBVisibilityOperation restore, void *context)
{
    pthread_mutex_lock(&s->lock);
    if (s->busy || s->restartPrepared) { pthread_mutex_unlock(&s->lock); return EBUSY; }
    s->busy = true;
    pthread_mutex_unlock(&s->lock);
    // Explicit app resurrection also validates the physical entry when the
    // cached phase says visible. External writers/reboots can invalidate it.
    int result = restore(context);
    return jb_visibility_finish(s, result == 0 ? JB_VISIBLE : JB_VISIBILITY_FAILED,
        result, result, restore, context);
}
static inline int jb_visibility_prepare_restart(JBVisibilityState *s,
    JBVisibilityOperation restore, void *context)
{
    pthread_mutex_lock(&s->lock);
    if (s->busy || s->restartPrepared) { pthread_mutex_unlock(&s->lock); return EBUSY; }
    s->restartPrepared = true;
    s->busy = true;
    pthread_mutex_unlock(&s->lock);
    int result = restore(context);
    result = jb_visibility_finish(s, result == 0 ? JB_VISIBLE : JB_VISIBILITY_FAILED,
        result, result, restore, context);
    if (result != 0) {
        pthread_mutex_lock(&s->lock);
        s->restartPrepared = false;
        pthread_mutex_unlock(&s->lock);
    }
    return result;
}

static inline void jb_visibility_cancel_restart(JBVisibilityState *s)
{
    pthread_mutex_lock(&s->lock);
    if (!s->busy) s->restartPrepared = false;
    pthread_mutex_unlock(&s->lock);
}
#endif
