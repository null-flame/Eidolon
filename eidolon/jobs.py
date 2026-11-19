"""Background job system — long-running modules run in managed threads.

Any module can be backgrounded (`gen` for listener-type modules does it
automatically, `run --bg` for everything else). A job executes the module's
run(values) in a daemon thread; two conventions make management possible:

  * run() may either block (worker style) or return quickly after starting
    its own engines/threads (listener style). Either schedule works.
  * an optional stop() hook on the module lets `kill <id>` shut the engine
    down cleanly. Without it, a job can only end on its own.

The framework never touches the module's internals — start, list, stop; that
is the whole contract.
"""

import threading
import time


class Job:
    def __init__(self, jid, name, module, values):
        self.jid = jid
        self.name = name
        self.module = module
        self.values = values
        self.started = time.time()
        self.status = "running"
        self.error = None
        self.thread = None

    @property
    def running(self):
        return self.status == "running"

    def label(self):
        desc = str(getattr(self.module, "DESCRIPTION", "") or "")[:32]
        return f"{self.name}{(' — ' + desc) if desc else ''}"


class JobManager:
    def __init__(self):
        self._jobs = {}
        self._lock = threading.RLock()
        self._next_id = 1

    def submit(self, module, name, values):
        with self._lock:
            jid = self._next_id
            self._next_id += 1
        job = Job(jid, name, module, values)

        def worker():
            try:
                module.run(values)
            except Exception as e:
                job.error = str(e)
                job.status = "failed"
                return
            if callable(getattr(module, "stop", None)):
                return  # engine keeps the job alive until stop() — a listener
            if job.status == "running":
                job.status = "exited"

        job.thread = threading.Thread(target=worker, name=f"eidolon-job-{jid}", daemon=True)
        with self._lock:
            self._jobs[jid] = job
        job.thread.start()
        return job

    def get(self, jid):
        with self._lock:
            return self._jobs.get(jid)

    def all(self):
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.jid)

    def active(self):
        return [j for j in self.all() if j.running]

    def kill(self, jid):
        """Stops a job via its module stop() hook. Returns (ok, message)."""
        job = self.get(jid)
        if job is None:
            return False, f"no such job: #{jid}"
        if not job.running:
            return False, f"job #{jid} is already {job.status}"
        stop = getattr(job.module, "stop", None)
        if not callable(stop):
            return False, f"module '{job.name}' has no stop() — cannot kill, it must end on its own"
        try:
            stop()
        except Exception as e:
            return False, f"stop() of job #{jid} raised: {e}"
        if job.thread is not None:
            job.thread.join(timeout=5)
        if job.status == "running":
            job.status = "stopped"
        return True, f"job #{jid} ({job.name}) stopped"

    def shutdown_all(self):
        """Best-effort stop of every running job (framework exit)."""
        stopped = 0
        for job in self.active():
            okk, _ = self.kill(job.jid)
            if okk:
                stopped += 1
        return stopped
