from threading import Lock, Condition

class RWLockWrite():
    ''' write preferring readers-wirter lock '''

    def __init__(self):
        self._lock = Lock()
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

def _init_synced_class(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self._rwlock = RWLockWrite()
    self._rl = self._rwlock.gen_rlock()
    self._wl = self._rwlock.gen_wlock()

def rlock_decorator(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        with self._rl:
            func(self, *args, **kwargs)

    return wrapper

def wlock_decorator(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        with self._wl:
            func(self, *args, **kwargs)

    return wrapper

def gen_synced_class(name, bases, rl_functions, wl_functions):

    attributes = {
        '__init__': wraps(bases[0].__init__)(_init_synced_class)
    }

    for func in wl_functions:
        attributes[func.__name__] = rlock_decorator(func)

    for func in rl_functions:
        attributes[func.__name__] = rlock_decorator(func)

    return type(name, bases, attributes)
