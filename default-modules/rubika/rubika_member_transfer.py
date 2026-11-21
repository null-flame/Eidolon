#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Eidolon module — Rubika Member Transfer (maxrubika edition)
============================================================
انتقال اعضا بین گروه و کانال شما — مبدأ و مقصد می‌تواند
گروه یا کانال باشد (g0 / c0 هر دو پشتیبانی می‌شوند).

تانسفرهای پشتیبانی‌شده:
  گروه   → گروه
  گروه   → کانال
  کانال  → گروه
  کانال  → کانال

حالت‌های کاری:
  1) تنظیم از طریق OPTIONS (source / target از قبل پر شده)
  2) تنظیم با دو دستور در subshell:  source <id>  و  target <id>
  3) تنظیم از داخل خود چت‌ها:
        /setsource  ← در چت مبدأ بفرستید
        /settarget  ← در چت مقصد بفرستید
  4) ورود دستی GUID اعضا:  manual  →  هر خط یک یا چند GUID
  5) دیدن اعضا در subshell:  view <id>  یا  members <id>
  6) اطلاعات چت:  info <id>   |   حساب شما:  whoami

ویژگی‌ها:
  - source/target می‌تواند GUID، لینک یا یوزرنیم باشد (تشخیص خودکار با get_guid)
  - اعضای گروه در یک فراخوانی (حداکثر ۱۰۰ عضو اول — محدودیت سرور روبیکا)
  - اعضای کانال با صفحه‌بندی start_id به‌صورت کامل دریافت می‌شوند
  - افزودن دسته‌ای با add_members (گروه g0 و کانال c0 هر دو)
  - تأخیر تصادفی بین دسته‌ها + استراحت دوره‌ای
  - تشخیص TOO_REQUESTS و توقف خودکار
  - فیلتر ربات‌ها، حذف تکراری‌ها و جلوگیری از افزودن دوباره
"""

import random
import threading
import time

try:
    from eidolon.utils import ok, err, info, warn
except ImportError:
    def ok(msg):   print(f"  [+] {msg}")
    def err(msg):  print(f"  [x] {msg}")
    def info(msg): print(f"  [.] {msg}")
    def warn(msg): print(f"  [!] {msg}")

# ──────────────────────────────────────────────────────────────────────────────
#  Module metadata
# ──────────────────────────────────────────────────────────────────────────────
NAME        = "Rubika Member Transfer"
DESCRIPTION = "Transfer members between your groups and channels (maxrubika) — group/channel in, group/channel out"
AUTHOR      = "null-flame"
VERSION     = "3.0.0"
CATEGORY    = "social"
MODULE_TYPE = "auxiliary"

RANK        = "normal"
TARGETS     = ["Rubika messenger (userbot session via maxrubika)"]
REFERENCES  = ["https://github.com/MEH2RAB/maxrubika", "https://MEH2RAB.GitHub.io/maxrubika"]
DEPS        = "pip install maxrubika"

# ──────────────────────────────────────────────────────────────────────────────
#  Options
# ──────────────────────────────────────────────────────────────────────────────
OPTIONS = {
    "session": {
        "value":    "mySession",
        "required": True,
        "desc":     "maxrubika session name",
    },
    "trigger": {
        "value":    "/transfer",
        "required": False,
        "desc":     "message text in a chat that starts the transfer",
    },
    "setup_source_trigger": {
        "value":    "/setsource",
        "required": False,
        "desc":     "message to send inside the SOURCE group/channel to bind it (used only if source is empty)",
    },
    "setup_target_trigger": {
        "value":    "/settarget",
        "required": False,
        "desc":     "message to send inside the TARGET group/channel to bind it (used only if target is empty)",
    },
    "source": {
        "value":    "",
        "required": False,
        "desc":     "GUID/link/username of the source GROUP or CHANNEL (optional — can be set via subshell or /setsource)",
    },
    "target": {
        "value":    "",
        "required": False,
        "desc":     "GUID/link/username of the TARGET GROUP or CHANNEL (optional — can be set via subshell or /settarget)",
    },
    "batch_size": {
        "value":    25,
        "required": False,
        "desc":     "members per add_members call (default 25)",
    },
    "add_delay": {
        "value":    5.0,
        "required": False,
        "desc":     "delay between add_members batches (seconds)",
    },
    "burst_size": {
        "value":    4,
        "required": False,
        "desc":     "number of batches before a short pause",
    },
    "burst_pause": {
        "value":    12.0,
        "required": False,
        "desc":     "short pause (seconds) after each burst of batches",
    },
    "skip_bots": {
        "value":    True,
        "required": False,
        "desc":     "skip bots (GUID starts with 'b0')",
    },
    "show_limit": {
        "value":    50,
        "required": False,
        "desc":     "max rows displayed by the view/members command",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
#  Colours
# ──────────────────────────────────────────────────────────────────────────────
class _C:
    RESET   = "\033[0m"
    RED     = "\033[38;2;255;60;100m"
    GREEN   = "\033[38;2;0;255;140m"
    YELLOW  = "\033[38;2;255;210;60m"
    CYAN    = "\033[38;2;0;240;255m"
    BLUE    = "\033[38;2;90;150;255m"
    PURPLE  = "\033[38;2;170;90;255m"
    PINK    = "\033[38;2;255;90;200m"
    GRAY    = "\033[38;2;120;130;150m"


# ──────────────────────────────────────────────────────────────────────────────
#  Module state
# ──────────────────────────────────────────────────────────────────────────────
_state = {
    "running":      False,
    "client":       None,
    "app_thread":   None,
    "transferring": False,
    "stop":         False,
    "mode":         "idle",      # idle | await_manual_ids
    "manual_buf":   [],
    "trigger":      "/transfer",
    "setup_source_trigger": "/setsource",
    "setup_target_trigger": "/settarget",
    "source":       "",
    "target":       "",
    "batch_size":   25,
    "add_delay":    5.0,
    "burst_size":   4,
    "burst_pause":  12.0,
    "skip_bots":    True,
    "show_limit":   50,
    "stats": {
        "discovered":  0,
        "filtered":    0,
        "batches":     0,
        "added":       0,
        "failed":      0,
        "skipped_bot": 0,
        "skipped_dup": 0,
        "started_at":  None,
    },
    "processed_guids": set(),
    "log": [],
}


def _emit(msg):
    info(str(msg))
    _state["log"].append(msg)
    if len(_state["log"]) > 500:
        _state["log"] = _state["log"][-250:]


def _sleep(base):
    if base > 0:
        time.sleep(base * random.uniform(0.8, 1.2))


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _kind_label(kind):
    return {"group": "گروه", "channel": "کانال", "user": "کاربر", "bot": "ربات"}.get(kind, kind or "?")


def _kind_from_guid(guid):
    if not isinstance(guid, str):
        return None
    return {
        "g0": "group",
        "c0": "channel",
        "u0": "user",
        "b0": "bot",
    }.get(guid[:2].lower())


def _kind_color(kind):
    return {
        "group":   _C.BLUE,
        "channel": _C.CYAN,
        "user":    _C.GREEN,
        "bot":     _C.GRAY,
    }.get(kind, _C.GRAY)


# ──────────────────────────────────────────────────────────────────────────────
#  استخراج فیلدهای پاسخ maxrubika
# ──────────────────────────────────────────────────────────────────────────────
def _extract_members(resp):
    """نرمال‌سازی خروجی get_group_members / get_channel_members به لیست."""
    for key in ("in_chat_members", "channel_members", "all_members", "members", "data", "list"):
        val = _get(resp, key)
        if isinstance(val, list):
            return val
    if isinstance(resp, list):
        return resp
    return []


def _extract_next_start_id(resp):
    """اگر سرور صفحه‌بندی برگرداند، شناسه صفحه بعد را استخراج می‌کند."""
    for key in ("next_start_id", "start_id", "next_id"):
        val = _get(resp, key)
        if val:
            return str(val)
    return None


def _member_guid(m):
    return _get(m, "member_guid") or _get(m, "guid") or _get(m, "user_guid")


def _member_name(m):
    first = _get(m, "first_name") or ""
    last  = _get(m, "last_name") or ""
    title = _get(m, "title") or ""
    return f"{first} {last}".strip() or title


def _member_username(m):
    return _get(m, "username") or ""


def _event_chat_guid(event):
    """GUID چت (گروه یا کانال) را از event استخراج می‌کند."""
    for attr in ("chat_guid", "group_guid", "channel_guid", "object_guid"):
        val = getattr(event, attr, None)
        if val:
            return val
    chat = getattr(event, "chat", None) or getattr(event, "group", None) or getattr(event, "channel", None)
    if chat is not None:
        for attr in ("guid", "chat_guid", "object_guid"):
            val = getattr(chat, attr, None)
            if val:
                return val
    return None


# ──────────────────────────────────────────────────────────────────────────────
#  شناسایی نوع چت (گروه / کانال / کاربر)
# ──────────────────────────────────────────────────────────────────────────────
def _resolve_chat(client, target):
    """
    هر ورودی (GUID / لینک / یوزرنیم) را به GUID تبدیل و نوعش را برمی‌گرداند.
    خروجی: (guid, kind) یا (None, None)
    """
    try:
        guid = client.get_guid(target)
    except Exception as e:
        _emit(f"❌ resolve failed for '{target}': {e}")
        return None, None
    if not isinstance(guid, str) or not guid:
        _emit(f"❌ could not resolve '{target}' to a GUID")
        return None, None
    return guid, _kind_from_guid(guid)


# ──────────────────────────────────────────────────────────────────────────────
#  دریافت اعضا (گروه: یک فراخوانی — کانال: صفحه‌بندی کامل)
# ──────────────────────────────────────────────────────────────────────────────
def _fetch_members(client, target, self_guid=None):
    """
    دریافت اعضا از گروه یا کانال.

    - گروه (g0):  get_group_members — سرور حداکثر ۱۰۰ عضو اول را برمی‌گرداند.
    - کانال (c0): get_channel_members با صفحه‌بندی start_id تا دریافت همه اعضا.
    ورودی می‌تواند GUID، لینک یا یوزرنیم باشد (داخلی با get_guid تبدیل می‌شود).
    """
    try:
        guid = client.get_guid(target)
    except Exception as e:
        _emit(f"❌ resolve failed for '{target}': {e}")
        return [], None

    kind = _kind_from_guid(guid)
    if kind not in ("group", "channel"):
        _emit(f"❌ '{target}' is a {_kind_label(kind)} — expected a group or channel")
        return [], kind

    members = []

    if kind == "channel":
        _emit(f"📥 fetching channel members: {guid}")
        start_id = None
        seen_ids = set()
        pages = 0
        while True:
            if _state["stop"]:
                _emit("⏹ stopped by operator")
                break
            try:
                resp = client.get_channel_members(guid, start_id=start_id)
            except Exception as e:
                _emit(f"❌ get_channel_members failed (page {pages + 1}): {e}")
                break
            page = _extract_members(resp)
            pages += 1
            _emit(f"   ↳ page {pages}: {len(page)} member(s)")
            members.extend(page)
            nxt = _extract_next_start_id(resp)
            # توقف وقتی صفحه خالی است یا شناسه صفحه بعد تولید نشده/تکرار شده است
            if not nxt or nxt == start_id or nxt in seen_ids or not page:
                break
            seen_ids.add(nxt)
            start_id = nxt
            _sleep(0.5)
    else:
        _emit(f"📥 fetching group members: {guid}")
        try:
            resp = client.get_group_members(guid)
        except Exception as e:
            _emit(f"❌ get_group_members failed: {e}")
            return [], kind
        members = _extract_members(resp)

    members = [m for m in members if _member_guid(m)]
    return members, kind


# ──────────────────────────────────────────────────────────────────────────────
#  فیلتر اعضا
# ──────────────────────────────────────────────────────────────────────────────
def _filter_members(members):
    result = []
    seen = set()
    s = _state["stats"]
    for m in members:
        guid = _member_guid(m)
        if not guid:
            continue
        if _state["skip_bots"] and guid.startswith("b0"):
            s["skipped_bot"] += 1
            continue
        if guid in seen:
            continue
        seen.add(guid)
        if guid in _state["processed_guids"]:
            s["skipped_dup"] += 1
            continue
        result.append(guid)
    return result


# ──────────────────────────────────────────────────────────────────────────────
#  افزودن دسته‌بندی‌شده (پیشفرض ۲۵تایی)
# ──────────────────────────────────────────────────────────────────────────────
def _add_batches(client, target_guid, guids):
    s = _state["stats"]
    batch_size = _state["batch_size"]
    total_batches = (len(guids) + batch_size - 1) // batch_size

    for i in range(0, len(guids), batch_size):
        if _state["stop"]:
            _emit("⏹ stopped by operator")
            return

        batch = guids[i:i + batch_size]
        batch_num = i // batch_size + 1

        try:
            client.add_members(target_guid, members=batch)
            s["added"] += len(batch)
            s["batches"] += 1
            _state["processed_guids"].update(batch)
            _emit(
                f"✅ batch {batch_num}/{total_batches}: "
                f"added {len(batch)} members"
            )

            if s["batches"] % _state["burst_size"] == 0:
                _emit(
                    f"⏸ burst pause — {s['batches']} batches, "
                    f"resting {_state['burst_pause']}s"
                )
                _sleep(_state["burst_pause"])
            else:
                _sleep(_state["add_delay"])

        except Exception as e:
            s["failed"] += len(batch)
            err_text = str(e)
            _emit(f"❌ batch {batch_num} failed: {e}")

            if "TOO_REQUESTS" in err_text or "Too many requests" in err_text \
                    or "rate_limited" in err_text.lower():
                _emit("🛑 rate limit detected — aborting transfer")
                _state["stop"] = True
                return


# ──────────────────────────────────────────────────────────────────────────────
#  Worker اصلی انتقال (گروه/کانال → گروه/کانال)
# ──────────────────────────────────────────────────────────────────────────────
def _transfer_worker(client, source_target, target_target, self_guid=None):
    _state["transferring"] = True
    _state["stop"] = False
    s = _state["stats"]
    s["started_at"] = time.time()

    try:
        src_guid, src_kind = _resolve_chat(client, source_target)
        dst_guid, dst_kind = _resolve_chat(client, target_target)

        if not src_guid or not dst_guid:
            _emit("❌ transfer aborted — invalid source or target")
            return
        if src_kind not in ("group", "channel"):
            _emit(f"❌ source must be a group or channel — got {_kind_label(src_kind)}")
            return
        if dst_kind not in ("group", "channel"):
            _emit(f"❌ target must be a group or channel — got {_kind_label(dst_kind)}")
            return
        if src_guid == dst_guid:
            _emit("❌ source and target are the same chat")
            return

        _emit(f"🔗 route: {_kind_label(src_kind)}/{src_guid} → {_kind_label(dst_kind)}/{dst_guid}")

        members, _ = _fetch_members(client, src_guid, self_guid)
        s["discovered"] = len(members)

        _emit(f"🧹 filtering {len(members)} members")
        guids = _filter_members(members)
        s["filtered"] = len(guids)
        _emit(
            f"📋 {len(guids)} valid members to add "
            f"(skipped_bot={s['skipped_bot']} skipped_dup={s['skipped_dup']})"
        )

        if not guids:
            _emit("ℹ no members to add")
            return

        _emit(
            f"➕ adding members to {_kind_label(dst_kind)}: {dst_guid} "
            f"in batches of {_state['batch_size']}"
        )
        _add_batches(client, dst_guid, guids)

    finally:
        _state["transferring"] = False
        elapsed = (time.time() - s["started_at"]) if s["started_at"] else 0
        _emit(
            f"📊 TRANSFER DONE — discovered={s['discovered']} "
            f"filtered={s['filtered']} added={s['added']} "
            f"failed={s['failed']} time={elapsed:.1f}s"
        )


# ──────────────────────────────────────────────────────────────────────────────
#  Worker انتقال دستی (لیست GUID → گروه/کانال)
# ──────────────────────────────────────────────────────────────────────────────
def _manual_transfer_worker(client, target_target, guids):
    _state["transferring"] = True
    _state["stop"] = False
    s = _state["stats"]
    s["started_at"] = time.time()
    s["discovered"] = len(guids)

    try:
        dst_guid, dst_kind = _resolve_chat(client, target_target)
        if not dst_guid or dst_kind not in ("group", "channel"):
            _emit(f"❌ target must be a group or channel — got {_kind_label(dst_kind)}")
            return

        valid = []
        for g in guids:
            g = g.strip()
            if not g:
                continue
            if _state["skip_bots"] and g.startswith("b0"):
                s["skipped_bot"] += 1
                continue
            if g in _state["processed_guids"]:
                s["skipped_dup"] += 1
                continue
            valid.append(g)

        s["filtered"] = len(valid)
        _emit(f"📋 {len(valid)} valid manual GUID(s) to add")

        if not valid:
            _emit("ℹ no GUIDs to add")
            return

        _emit(f"➕ adding manual members to {_kind_label(dst_kind)}: {dst_guid}")
        _add_batches(client, dst_guid, valid)

    finally:
        _state["transferring"] = False
        elapsed = (time.time() - s["started_at"]) if s["started_at"] else 0
        _emit(
            f"📊 MANUAL TRANSFER DONE — discovered={s['discovered']} "
            f"filtered={s['filtered']} added={s['added']} "
            f"failed={s['failed']} time={elapsed:.1f}s"
        )


# ──────────────────────────────────────────────────────────────────────────────
#  نمایش اعضا (دستور view/members)
# ──────────────────────────────────────────────────────────────────────────────
def _show_members(client, target):
    """نمایش اعضای یک گروه یا کانال با متد مربوطه (دیدن)."""
    members, kind = _fetch_members(client, target)
    if kind is None:
        return

    limit = max(1, _state["show_limit"])
    label = _kind_label(kind)
    print(f"\n  {_C.PURPLE}╭─ MEMBERS ({label}) ─────────────────────────────────╮{_C.RESET}")
    print(f"  {_C.PURPLE}│{_C.RESET}  target : {_C.CYAN}{target}{_C.RESET}")
    print(f"  {_C.PURPLE}│{_C.RESET}  count  : {_C.GREEN}{len(members)}{_C.RESET}"
          f"   (showing first {_C.YELLOW}{min(len(members), limit)}{_C.RESET})")
    print(f"  {_C.PURPLE}│{_C.RESET}")
    for i, m in enumerate(members[:limit], 1):
        guid = _member_guid(m) or "—"
        name = _member_name(m) or "—"
        user = _member_username(m)
        tag  = f" @{user}" if user else ""
        kcol = _kind_color(_kind_from_guid(guid))
        print(
            f"  {_C.PURPLE}│{_C.RESET}  "
            f"{_C.GRAY}{i:>3}. {_C.RESET}"
            f"{kcol}{guid}{_C.RESET}  "
            f"{name}{_C.GRAY}{tag}{_C.RESET}"
        )
    if len(members) > limit:
        print(f"  {_C.PURPLE}│{_C.RESET}  {_C.GRAY}… {len(members) - limit} more (raise show_limit option){_C.RESET}")
    print(f"  {_C.PURPLE}╰─────────────────────────────────────────────────────╯{_C.RESET}\n")


# ──────────────────────────────────────────────────────────────────────────────
#  اطلاعات چت (دستور info)
# ──────────────────────────────────────────────────────────────────────────────
def _show_info(client, target):
    try:
        resp = client.get_chat_info(target)
    except Exception as e:
        _emit(f"❌ get_chat_info failed: {e}")
        return

    chat = _get(resp, "chat") or resp
    guid = _get(chat, "chat_id") or _get(chat, "guid") or ""
    kind = _kind_from_guid(str(guid))
    print(f"\n  {_C.PURPLE}╭─ CHAT INFO ─────────────────────────────────────────╮{_C.RESET}")
    print(f"  {_C.PURPLE}│{_C.RESET}  kind    : {_kind_color(kind)}{_kind_label(kind)}{_C.RESET}")
    for label, key in (("guid", "chat_id"), ("title", "title"), ("username", "username"),
                       ("description", "description"), ("members", "members_count"),
                       ("type", "chat_type")):
        val = _get(chat, key)
        if val not in (None, ""):
            print(f"  {_C.PURPLE}│{_C.RESET}  {label:<7} : {str(val)[:80]}")
    print(f"  {_C.PURPLE}╰─────────────────────────────────────────────────────╯{_C.RESET}\n")


# ──────────────────────────────────────────────────────────────────────────────
#  اطلاعات حساب ورود (دستور whoami)
# ──────────────────────────────────────────────────────────────────────────────
def _show_whoami(client):
    try:
        me = client.get_me()
    except Exception as e:
        _emit(f"❌ get_me failed: {e}")
        return
    first = _get(me, "first_name") or ""
    last  = _get(me, "last_name") or ""
    print(f"\n  {_C.PURPLE}╭─ MY ACCOUNT ────────────────────────────────────────╮{_C.RESET}")
    print(f"  {_C.PURPLE}│{_C.RESET}  name    : {' '.join((first, last)).strip() or '—'}")
    print(f"  {_C.PURPLE}│{_C.RESET}  guid    : {_get(me, 'guid') or _get(me, 'chat_id') or '—'}")
    user = _get(me, "username")
    if user:
        print(f"  {_C.PURPLE}│{_C.RESET}  username: @{user}")
    phone = _get(me, "phone")
    if phone:
        print(f"  {_C.PURPLE}│{_C.RESET}  phone   : {phone}")
    print(f"  {_C.PURPLE}╰─────────────────────────────────────────────────────╯{_C.RESET}\n")


# ──────────────────────────────────────────────────────────────────────────────
#  Subshell
# ──────────────────────────────────────────────────────────────────────────────
def _prompt_fn():
    s = _state["stats"]
    if _state["mode"] == "await_manual_ids":
        return (
            f"  {_C.YELLOW}manual-ids{_C.RESET} "
            f"{_C.GRAY}(blank line = done){_C.RESET} "
            f"{_C.PINK}❯{_C.RESET} "
        )
    flag = "▶" if _state["transferring"] else "■"
    return (
        f"  {_C.PINK}transfer{_C.RESET} {_C.GRAY}{flag} "
        f"{s['added']}a/{s['failed']}f{_C.RESET} {_C.PINK}❯{_C.RESET} "
    )


def _completer(text, line, begidx, endidx):
    cmds = [
        "status", "log", "stop", "help",
        "source", "target", "view", "members",
        "manual", "start", "run", "info", "whoami", "me",
    ]
    return [c for c in cmds if c.startswith(text)]


def _subshell_handler(line):
    line = line.strip()

    # ── حالت ورود دستی GUID ───────────────────────────────────────────────────
    if _state["mode"] == "await_manual_ids":
        if line == "" or line.lower() in ("done", "end", "finish"):
            guids = []
            for chunk in _state["manual_buf"]:
                for part in chunk.replace(",", " ").split():
                    part = part.strip()
                    if part:
                        guids.append(part)

            _state["manual_buf"] = []
            _state["mode"] = "idle"

            if not guids:
                _emit("⚠ no GUIDs entered — manual mode cancelled")
                return

            target = _state["target"]
            if not target:
                _emit("❌ target is not set — use: target <id>")
                return

            _emit(f"🚀 starting manual transfer of {len(guids)} GUID(s)")
            threading.Thread(
                target=_manual_transfer_worker,
                args=(_state["client"], target, guids),
                daemon=True,
                name="eidolon-manual-transfer",
            ).start()
            return

        _state["manual_buf"].append(line)
        _emit(f"➕ buffered: {line[:80]}{'…' if len(line) > 80 else ''}")
        return

    # ── دستورات عادی ─────────────────────────────────────────────────────────
    parts = line.split(maxsplit=1)
    if not parts:
        return
    cmd = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""
    s = _state["stats"]

    if cmd == "status":
        elapsed = (time.time() - s["started_at"]) if s["started_at"] else 0
        src_kind = _kind_from_guid(_state["source"])
        dst_kind = _kind_from_guid(_state["target"])
        print(f"\n  {_C.PURPLE}╭─ TRANSFER STATUS ───────────────────────────────────╮{_C.RESET}")
        print(f"  {_C.PURPLE}│{_C.RESET}  listener      : "
              f"{_C.GREEN + 'ONLINE' if _state['running'] else _C.RED + 'OFFLINE'}{_C.RESET}")
        print(f"  {_C.PURPLE}│{_C.RESET}  transferring  : "
              f"{_C.GREEN + 'YES' if _state['transferring'] else _C.GRAY + 'no'}{_C.RESET}")
        print(f"  {_C.PURPLE}│{_C.RESET}  source        : "
              f"{_kind_color(src_kind)}{(src_kind or '—')}{_C.RESET} {_C.CYAN}{_state['source'] or '—'}{_C.RESET}")
        print(f"  {_C.PURPLE}│{_C.RESET}  target        : "
              f"{_kind_color(dst_kind)}{(dst_kind or '—')}{_C.RESET} {_C.CYAN}{_state['target'] or '—'}{_C.RESET}")
        print(f"  {_C.PURPLE}│{_C.RESET}  batch_size    : {_state['batch_size']}")
        print(f"  {_C.PURPLE}│{_C.RESET}  discovered    : {s['discovered']}")
        print(f"  {_C.PURPLE}│{_C.RESET}  filtered      : {s['filtered']}")
        print(f"  {_C.PURPLE}│{_C.RESET}  batches       : {s['batches']}")
        print(f"  {_C.PURPLE}│{_C.RESET}  added         : {_C.GREEN}{s['added']}{_C.RESET}")
        print(f"  {_C.PURPLE}│{_C.RESET}  failed        : {_C.RED}{s['failed']}{_C.RESET}")
        print(f"  {_C.PURPLE}│{_C.RESET}  bots skipped  : {_C.GRAY}{s['skipped_bot']}{_C.RESET}")
        print(f"  {_C.PURPLE}│{_C.RESET}  dups skipped  : {_C.GRAY}{s['skipped_dup']}{_C.RESET}")
        print(f"  {_C.PURPLE}│{_C.RESET}  elapsed       : {elapsed:.1f}s")
        print(f"  {_C.PURPLE}╰─────────────────────────────────────────────────────╯{_C.RESET}\n")

    elif cmd == "log":
        if not _state["log"]:
            print(f"    {_C.GRAY}(empty){_C.RESET}")
            return
        for e in _state["log"][-40:]:
            print(f"    {e}")

    elif cmd == "stop":
        _state["stop"] = True
        _emit("⏹ stop requested")

    elif cmd in ("source", "set-source"):
        if not arg:
            _emit("usage: source <GUID|link|username of group or channel>")
            return
        _state["source"] = arg
        _emit(f"✅ source set → {arg}")

    elif cmd in ("target", "set-target"):
        if not arg:
            _emit("usage: target <GUID|link|username of group or channel>")
            return
        _state["target"] = arg
        _emit(f"✅ target set → {arg}")

    elif cmd in ("view", "members"):
        if not arg:
            _emit("usage: view <GUID|link|username of group or channel>")
            return
        if _state["transferring"]:
            _emit("⚠ a transfer is running — try again after it finishes")
            return
        _show_members(_state["client"], arg)

    elif cmd == "info":
        if not arg:
            _emit("usage: info <GUID|link|username>")
            return
        _show_info(_state["client"], arg)

    elif cmd in ("whoami", "me"):
        _show_whoami(_state["client"])

    elif cmd == "manual":
        if _state["transferring"]:
            _emit("⚠ a transfer is already running")
            return
        _state["mode"] = "await_manual_ids"
        _state["manual_buf"] = []
        _emit("📝 manual mode — enter GUIDs (comma/space separated), blank line to start")

    elif cmd in ("start", "run"):
        if _state["transferring"]:
            _emit("⚠ a transfer is already running")
            return
        if not _state["source"] or not _state["target"]:
            _emit("❌ source and target must be set first")
            _emit("   options:  source <id> / target <id>")
            _emit("   or send /setsource in source chat and /settarget in target chat")
            return
        _emit("🚀 starting transfer")
        threading.Thread(
            target=_transfer_worker,
            args=(
                _state["client"],
                _state["source"],
                _state["target"],
                None,
            ),
            daemon=True,
            name="eidolon-transfer-worker",
        ).start()

    elif cmd in ("help", "?"):
        print(f"    {_C.CYAN}source <id>{_C.RESET}     set source (group OR channel: GUID/link/username)")
        print(f"    {_C.CYAN}target <id>{_C.RESET}     set target (group OR channel)")
        print(f"    {_C.CYAN}view <id>{_C.RESET}       view members of a group or channel")
        print(f"    {_C.CYAN}info <id>{_C.RESET}       show chat info")
        print(f"    {_C.CYAN}whoami{_C.RESET}          show logged-in account info")
        print(f"    {_C.CYAN}manual{_C.RESET}          enter member GUIDs manually")
        print(f"    {_C.CYAN}start{_C.RESET}           start group/channel → group/channel transfer")
        print(f"    {_C.CYAN}status{_C.RESET}          show live counters")
        print(f"    {_C.CYAN}log{_C.RESET}             tail last 40 events")
        print(f"    {_C.CYAN}stop{_C.RESET}            abort current transfer")
        print(f"    {_C.CYAN}back{_C.RESET} / {_C.CYAN}exit{_C.RESET}    leave subshell")
        print()
        print(f"    {_C.GRAY}tip:{_C.RESET} if source/target not set in options,")
        print(f"         send {_C.YELLOW}{_state['setup_source_trigger']}{_C.RESET} in the SOURCE group/channel")
        print(f"         and {_C.YELLOW}{_state['setup_target_trigger']}{_C.RESET} in the TARGET group/channel")

    else:
        print(f"    {_C.RED}unknown:{_C.RESET} {cmd}  — try 'help'")


def _on_exit():
    _state["stop"] = True
    _state["running"] = False
    _state["mode"] = "idle"
    _state["client"] = None
    _state["app_thread"] = None


# ──────────────────────────────────────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────────────────────────────────────
def run(opts):
    if _state["running"]:
        print(f"  {_C.YELLOW}⚠{_C.RESET} a transfer listener is already running")
        return

    try:
        from maxrubika import Messenger
    except ImportError:
        print(f"  {_C.RED}✗{_C.RESET} maxrubika is not installed — pip install maxrubika")
        return

    # ── خواندن گزینه‌ها ────────────────────────────────────────────────────────
    session = str(opts.get("session") or "mySession")
    trigger = str(opts.get("trigger") or "/transfer")
    setup_source_trigger = str(opts.get("setup_source_trigger") or "/setsource")
    setup_target_trigger = str(opts.get("setup_target_trigger") or "/settarget")
    source = str(opts.get("source") or OPTIONS["source"]["value"] or "").strip()
    target = str(opts.get("target") or OPTIONS["target"]["value"] or "").strip()

    def num(k, default, cast=float):
        try:
            return cast(opts.get(k, default))
        except (TypeError, ValueError):
            return default

    _state.update({
        "running":      True,
        "transferring": False,
        "stop":         False,
        "mode":         "idle",
        "manual_buf":   [],
        "trigger":      trigger,
        "setup_source_trigger": setup_source_trigger,
        "setup_target_trigger": setup_target_trigger,
        "source":       source,
        "target":       target,
        "batch_size":   max(1, num("batch_size", 25, int)),
        "add_delay":    max(0.0, num("add_delay", 5.0)),
        "burst_size":   max(1, num("burst_size", 4, int)),
        "burst_pause":  max(0.0, num("burst_pause", 12.0)),
        "skip_bots":    bool(opts.get("skip_bots", True)),
        "show_limit":   max(1, num("show_limit", 50, int)),
        "stats": {
            "discovered": 0, "filtered": 0, "batches": 0,
            "added": 0, "failed": 0, "skipped_bot": 0, "skipped_dup": 0,
            "started_at": None,
        },
        "processed_guids": set(),
        "log": [],
    })

    # ── ساخت کلاینت ───────────────────────────────────────────────────────────
    try:
        app = Messenger(session)
    except Exception as e:
        print(f"  {_C.RED}✗{_C.RESET} client init failed: {e}")
        _state["running"] = False
        return

    _state["client"] = app

    # ── ثبت لیسننر تریگرها ────────────────────────────────────────────────────
    @app.on_new_message()
    async def _handler(event):
        if not _state["running"]:
            return
        try:
            text = event.text
        except AttributeError:
            return
        if not text:
            return

        parts = text.strip().split(maxsplit=1)
        if not parts:
            return
        cmd = parts[0]

        # ── /setsource → bind current chat (group or channel) as source ──
        if cmd == _state["setup_source_trigger"]:
            chat = _event_chat_guid(event)
            if not chat:
                _emit("⚠ cannot detect chat id from event")
                return
            if chat.startswith(("u0", "b0")):
                _emit(f"⚠ {_state['setup_source_trigger']} must be sent inside a group or channel (got {chat})")
                return
            kind = _kind_from_guid(chat)
            old = _state["source"]
            _state["source"] = chat
            _emit(f"✅ source bound from {_kind_label(kind)} → {chat}" if not old
                  else f"🔄 source updated: {old} → {chat}")
            return

        # ── /settarget → bind current chat (group or channel) as target ──
        if cmd == _state["setup_target_trigger"]:
            chat = _event_chat_guid(event)
            if not chat:
                _emit("⚠ cannot detect chat id from event")
                return
            if chat.startswith(("u0", "b0")):
                _emit(f"⚠ {_state['setup_target_trigger']} must be sent inside a group or channel (got {chat})")
                return
            kind = _kind_from_guid(chat)
            old = _state["target"]
            _state["target"] = chat
            _emit(f"✅ target bound from {_kind_label(kind)} → {chat}" if not old
                  else f"🔄 target updated: {old} → {chat}")
            return

        # ── main transfer trigger ─────────────────────────────────────────
        if cmd != _state["trigger"]:
            return

        if _state["transferring"]:
            _emit("⚠ transfer already running")
            return
        if not _state["source"] or not _state["target"]:
            _emit(
                f"❌ source/target not set — send "
                f"{_state['setup_source_trigger']} in source chat and "
                f"{_state['setup_target_trigger']} in target chat"
            )
            return

        self_guid = getattr(event, "author_guid", None)
        _emit("🚀 trigger received — starting transfer")
        threading.Thread(
            target=_transfer_worker,
            args=(app, _state["source"], _state["target"], self_guid),
            daemon=True,
            name="eidolon-transfer-worker",
        ).start()

    # ── اجرای app در ترد پس‌زمینه ─────────────────────────────────────────────
    _state["app_thread"] = threading.Thread(
        target=app.run,
        daemon=True,
        name="eidolon-transfer-listener",
    )
    _state["app_thread"].start()

    # ── خلاصه وضعیت ───────────────────────────────────────────────────────────
    print(f"  {_C.PURPLE}◈{_C.RESET} listener online  · {session}")
    print(f"  {_C.PURPLE}◈{_C.RESET} transfer trig  : {_C.YELLOW}{trigger}{_C.RESET}")
    print(f"  {_C.PURPLE}◈{_C.RESET} setup triggers : "
          f"{_C.YELLOW}{setup_source_trigger}{_C.RESET} / "
          f"{_C.YELLOW}{setup_target_trigger}{_C.RESET}")
    print(f"  {_C.PURPLE}◈{_C.RESET} source         : {_C.CYAN}{source or '(not set)'}{_C.RESET}  {_C.GRAY}(group or channel){_C.RESET}")
    print(f"  {_C.PURPLE}◈{_C.RESET} target         : {_C.CYAN}{target or '(not set)'}{_C.RESET}  {_C.GRAY}(group or channel){_C.RESET}")
    if not source:
        print(f"  {_C.PURPLE}◈{_C.RESET}   → send {_C.YELLOW}{setup_source_trigger}{_C.RESET} inside SOURCE group/channel")
    if not target:
        print(f"  {_C.PURPLE}◈{_C.RESET}   → send {_C.YELLOW}{setup_target_trigger}{_C.RESET} inside TARGET group/channel")
    print(f"  {_C.PURPLE}◈{_C.RESET} batch_size     : {_state['batch_size']}")
    print(f"  {_C.PURPLE}◈{_C.RESET} add_delay      : {_state['add_delay']}s")
    print(f"  {_C.PURPLE}◈{_C.RESET} burst          : {_state['burst_size']} batches "
          f"/ {_state['burst_pause']}s pause")
    print(f"  {_C.PURPLE}◈{_C.RESET} type {_C.CYAN}help{_C.RESET} in subshell\n")

    # ── ورود به subshell ──────────────────────────────────────────────────────
    shell = globals().get("EIDOLON_SHELL")
    if shell is not None and hasattr(shell, "enter_subshell"):
        shell.enter_subshell(
            handler=_subshell_handler,
            completer=_completer,
            prompt_fn=_prompt_fn,
            on_exit=_on_exit,
        )
        return

    # ── حالت standalone ───────────────────────────────────────────────────────
    try:
        while _state["running"]:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        _on_exit()
