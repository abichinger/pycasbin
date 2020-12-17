from threading import RLock, Condition

class RWLockWrite():
    ''' write preferring readers-wirter lock '''

    def __init__(self):
        self._lock = RLock()
        self._cond = Condition(self._lock)
        self._active_readers = 0
        self._waiting_writers = 0
        self._writer_active = False

    def aquire_read(self):
        with self._lock:
            while self._waiting_writers > 0 or self._writer_active:
                self._cond.wait()
            self._active_readers += 1
    
    def release_read(self):
        with self._lock:
            self._active_readers -= 1
            if self._active_readers == 0:
                self._cond.notify_all()

    def aquire_write(self):
        with self._lock:
            self._waiting_writers += 1
            while self._active_readers > 0 or self._writer_active:
                self._cond.wait()
            self._waiting_writers -= 1
            self._writer_active = True

    def release_write(self):
        with self._lock:
            self._writer_active = False
            self._cond.notify_all()

    def gen_rlock(self):
        return ReadRWLock(self)

    def gen_wlock(self):
        return WriteRWLock(self)

class ReadRWLock():

    def __init__(self, rwlock):
        self.rwlock = rwlock

    def __enter__(self):
        self.rwlock.aquire_read()

    def __exit__(self, exc_type, exc_value, traceback):
        self.rwlock.release_read()
        return False

class WriteRWLock():

    def __init__(self, rwlock):
        self.rwlock = rwlock

    def __enter__(self):
        self.rwlock.aquire_write()

    def __exit__(self, exc_type, exc_value, traceback):
        self.rwlock.release_write()
        return False

from functools import wraps

def _rlock_decorator(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        with self._rl:
            func(self, *args, **kwargs)

    return wrapper

def _wlock_decorator(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        with self._wl:
            func(self, *args, **kwargs)

    return wrapper

def _get_init(synced_class):
    
    def __init__(self, *args, **kwargs):
        self._rwlock = RWLockWrite()
        self._rl = self._rwlock.gen_rlock()
        self._wl = self._rwlock.gen_wlock()
        super(synced_class, self).__init__(*args, **kwargs)

    return __init__

def gen_synced_class(name, bases, rl_functions, wl_functions):

    attributes = {}

    for func in wl_functions:
        attributes[func.__name__] = _wlock_decorator(func)

    for func in rl_functions:
        attributes[func.__name__] = _rlock_decorator(func)

    synced_class = type(name, bases, attributes)
    synced_class.__init__ = _get_init(synced_class)
    return synced_class
