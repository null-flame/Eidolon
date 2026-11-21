#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ssghost — OBSIDIAN VANGUARD official tool (Eidolon module)
==========================================================
Palpable authority for a group or channel on Rubika, driven by a
maxrubika Messenger (userbot) session.

One "engage" pass can do ALL of the following (each step is toggle-able):

  ◼  retitle        rewrite the group/channel title           (edit_group_info / edit_channel_info)
  ◼  re-bio         rewrite the description                   (same API — description field)
  ◼  new avatar     wipe every stored avatar, upload the new one (delete_all_avatars + upload_avatar)
  ◼  purge          ban EVERY member — admins, bots and your own
                     session are exempt                       (get_group_admins/get_channel_admins + ban_members)
  ◼  unban          lift every existing ban on the chat       (unban_all_members)

Works identically for GROUPS (g0) and CHANNELS (c0) — the module
detects the chat kind and routes to the matching maxrubika API.

OPERATOR FLOW:
  install_local default-modules/rubika ; trust ssghost
  use ssghost ; set session mySession ; set target g0XXXX ; run
  (inner subshell:)
    target <GUID|link|username>   point the blade
    engage                        full purge: retitle + bio + avatar + ban
    rebrand                       retitle + bio + avatar only (no bans)
    unban                         lift all bans on the target
    banned                        count/list banned members
    status / log / stop           live ops

In-chat: send the `trigger` (default /ssghost) inside any group or
channel you administer to engage the full pass on that chat.

⚠  This module crashes communities by design. It only works on chats
   where the session holds admin/creator rights — Rubika enforces
   that server-side. Point it only at chats you own or administer.
"""

import os
import random
import threading
import time

try:
    from eidolon.utils import ok, err, info, warn, hr
except ImportError:
    def ok(msg):   print(f"  [+] {msg}")
    def err(msg):  print(f"  [x] {msg}")
    def info(msg): print(f"  [.] {msg}")
    def warn(msg): print(f"  [!] {msg}")
    def hr(color="-", width=58, char="─"): print(f"  {char * width}")

# ──────────────────────────────────────────────────────────────────────────────
#  Theme — Obsidian Vanguard
# ──────────────────────────────────────────────────────────────────────────────
class _OX:
    """Obsidian Vanguard palette — black glass edges on spectral purple."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    OBSID   = "\033[38;2;25;20;30m"      # obsidian black
    EDGE    = "\033[38;2;255;255;255m"   # white edge-glint
    VIOLET  = "\033[38;2;170;90;255m"    # spectral violet
    BLOOD   = "\033[38;2;255;60;100m"    # purge red
    LIVE    = "\033[38;2;0;255;140m"     # alive green
    ASH     = "\033[38;2;120;130;150m"   # ash gray

BANNER = r"""
   ◼◼◼◼   ◼   ◼  ◼◼◼◼◼   ◼◼◼◼   ◼     ◼     OBSIDIAN VANGUARD
  ◼     ◼ ◼   ◼  ◼      ◼     ◼  ◼     ◼     the blade of Ghost Union
  ◼     ◼ ◼   ◼  ◼◼◼◼   ◼     ◼  ◼     ◼     ssghost · v3.0.0
  ◼     ◼  ◼ ◼   ◼      ◼     ◼   ◼   ◼      forged in pressure
   ◼◼◼◼     ◼    ◼◼◼◼◼   ◼◼◼◼      ◼◼◼       first to engage
"""

TAGLINE = "Forged in pressure. Sharpened in silence. First to engage."

# ──────────────────────────────────────────────────────────────────────────────
#  Module metadata
# ──────────────────────────────────────────────────────────────────────────────
NAME        = "ssghost"
VERSION     = "3.0.0"
DESCRIPTION = "OBSIDIAN VANGUARD official — retitle/re-bio/re-avatar a Rubika group or channel and purge every member (admins & bots exempt) via maxrubika"
AUTHOR      = "null-flame"
CATEGORY    = "social"
MODULE_TYPE = "auxiliary"

RANK        = "great"
TARGETS     = ["Rubika messenger — groups (g0) and channels (c0), session must hold admin/creator rights"]
REFERENCES  = ["https://github.com/MEH2RAB/maxrubika", "https://MEH2RAB.GitHub.io/maxrubika"]
DEPS        = "pip install maxrubika"
TAGS        = ("obsidian-vanguard", "rubika", "maxrubika")

# ──────────────────────────────────────────────────────────────────────────────
#  Options
# ──────────────────────────────────────────────────────────────────────────────
OPTIONS = {
    "session": {
        "value":    "mySession",
        "required": True,
        "desc":     "maxrubika session name (the admin account)",
    },
    "target": {
        "value":    "",
        "required": False,
        "desc":     "GUID/link/username of the group or channel to engage (can also be set via subshell 'target' or the in-chat trigger)",
    },
    "trigger": {
        "value":    "/ssghost",
        "required": False,
        "desc":     "message text inside a chat that engages the full pass on that chat",
    },
    "new_name": {
        "value":    "",
        "required": False,
        "desc":     "new title for the group/channel (empty = leave title untouched)",
    },
    "new_bio": {
        "value":    "",
        "required": False,
        "desc":     "new description/bio (empty = leave bio untouched)",
    },
    "avatar": {
        "value":    "",
        "required": False,
        "desc":     "path to the new avatar image (empty = leave avatars untouched)",
    },
    "wipe_avatars": {
        "value":    True,
        "required": False,
        "desc":     "delete ALL current avatars before uploading the new one",
    },
    "ban_all": {
        "value":    True,
        "required": False,
        "desc":     "engage the purge: ban every member (admins, bots and this session are exempt)",
    },
    "protect_admins": {
        "value":    True,
        "required": False,
        "desc":     "never ban admins/creator (recommended: keep True)",
    },
    "protect_bots": {
        "value":    True,
        "required": False,
        "desc":     "never ban bots (GUID starts with 'b0')",
    },
    "ban_chunk": {
        "value":    10,
        "required": False,
        "desc":     "members per ban_members call (default 10)",
    },
    "ban_delay": {
        "value":    2.0,
        "required": False,
        "desc":     "delay between ban chunks (seconds)",
    },
    "unban_after": {
        "value":    False,
        "required": False,
        "desc":     "engage unban_all_members right after the purge lifts every ban",
    },
    "dry_run": {
        "value":    True,
        "required": False,
        "desc":     "simulate everything: show exactly what would happen, send nothing (recommended first pass)",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
#  Module state
# ──────────────────────────────────────────────────────────────────────────────
_state = {
    "running":        False,
    "client":         None,
    "app_thread":     None,
    "engaging":       False,
    "stop":           False,
    "trigger":        "/ssghost",
    "target":         "",
    "new_name":       "",
    "new_bio":        "",
    "avatar":         "",
    "wipe_avatars":   True,
    "ban_all":        True,
    "protect_admins": True,
    "protect_bots":   True,
    "ban_chunk":      10,
    "ban_delay":      2.0,
    "unban_after":    False,
    "dry_run":        True,
    "stats": {
        "kind":        None,   # group | channel
        "guid":        None,
        "members":     0,
        "admins":      0,
        "bots":        0,
        "banned":      0,
        "ban_failed":  0,
        "unbanned":    0,
        "retitled":    False,
        "rebioed":     False,
        "avatars_old": 0,
        "avatars_new": 0,
        "started_at":  None,
    },
    "log": [],
}


def _o(msg):
    """Obsidian-logger — every line keeps the squad flavour."""
    print(f"  {_OX.VIOLET}◼{_OX.RESET} {msg}")
    _state["log"].append(str(msg))
    if len(_state["log"]) > 500:
        _state["log"] = _state["log"][-250:]


def _sleep(base):
    if base > 0:
        time.sleep(base * random.uniform(0.8, 1.2))


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _kind_from_guid(guid):
    if not isinstance(guid, str):
        return None
    return {"g0": "group", "c0": "channel", "u0": "user", "b0": "bot"}.get(guid[:2].lower())


def _kind_label(kind):
    return {"group": "GROUP", "channel": "CHANNEL"}.get(kind, (kind or "?").upper())


# ──────────────────────────────────────────────────────────────────────────────
#  maxrubika plumbing — kinds, admins, members
# ──────────────────────────────────────────────────────────────────────────────
def _resolve_target(client, target):
    """GUID/link/username → (guid, kind) — kind must be group or channel."""
    try:
        guid = client.get_guid(target)
    except Exception as e:
        _o(f"{_OX.BLOOD}✗{_OX.RESET} resolve failed for '{target}' — {e}")
        return None, None
    if not isinstance(guid, str) or not guid:
        _o(f"{_OX.BLOOD}✗{_OX.RESET} could not resolve '{target}' to a GUID")
        return None, None
    kind = _kind_from_guid(guid)
    if kind not in ("group", "channel"):
        _o(f"{_OX.BLOOD}✗{_OX.RESET} '{target}' is a {kind or 'unknown'} chat — only groups and channels are valid targets")
        return None, kind
    return guid, kind


def _fetch_admin_guids(client, guid, kind):
    """The untouchables — admin GUID set (creator included)."""
    admins = set()
    try:
        if kind == "group":
            resp = client.get_group_admins(guid, show_admin_guids=True)
        else:
            resp = client.get_channel_admins(guid, show_admin_guids=True)
        for a in _get(resp, "admins") or _get(resp, "in_chat_members") or []:
            g = a if isinstance(a, str) else (_get(a, "member_guid") or _get(a, "guid") or "")
            if g:
                admins.add(g)
    except Exception as e:
        _o(f"{_OX.ASH}ℹ admin listing unavailable (continuing without protect list) — {e}")
    return admins


def _fetch_all_members(client, guid, kind):
    """
    Every member GUID of the chat.
      group   : get_group_members — server returns the first 100 in one call
      channel : get_channel_members with full start_id pagination
    """
    members = []
    if kind == "channel":
        start_id, seen, pages = None, set(), 0
        while True:
            if _state["stop"]:
                return members
            try:
                resp = client.get_channel_members(guid, start_id=start_id)
            except Exception as e:
                _o(f"{_OX.BLOOD}✗{_OX.RESET} get_channel_members failed (page {pages + 1}) — {e}")
                break
            raw = _get(resp, "channel_members") or _get(resp, "in_chat_members") \
                or _get(resp, "all_members") or _get(resp, "members") or []
            page = list(raw)
            pages += 1
            members.extend(page)
            nxt = None
            for key in ("next_start_id", "start_id", "next_id"):
                val = _get(resp, key)
                if val:
                    nxt = str(val)
                    break
            if not nxt or nxt == start_id or nxt in seen or not page:
                break
            seen.add(nxt)
            start_id = nxt
            _sleep(0.5)
    else:
        try:
            resp = client.get_group_members(guid)
        except Exception as e:
            _o(f"{_OX.BLOOD}✗{_OX.RESET} get_group_members failed — {e}")
            return []
        members = list(_get(resp, "in_chat_members") or _get(resp, "members") or [])

    return [m for m in members if (m if isinstance(m, str) else
            (_get(m, "member_guid") or _get(m, "guid") or _get(m, "user_guid")))]


def _member_guid(m):
    if isinstance(m, str):
        return m
    return _get(m, "member_guid") or _get(m, "guid") or _get(m, "user_guid")


# ──────────────────────────────────────────────────────────────────────────────
#  The four blades
# ──────────────────────────────────────────────────────────────────────────────
def _blade_title(client, guid, kind, title):
    """◼ blade one — retitle (max 60 chars,uchte server limit)."""
    title = (title or "").strip()
    if not title:
        return False
    if len(title) > 60:
        warn(f"title exceeds Rubika's 60-char limit — truncating ({len(title)})")
        title = title[:60]
    if _state["dry_run"]:
        warn(f"DRY RUN — would retitle to: {title}")
        return True
    _o(f"retitling {_kind_label(kind)} → {_OX.EDGE}{title}{_OX.RESET}")
    if kind == "group":
        client.edit_group_info(guid, title=title)
    else:
        client.edit_channel_info(guid, title=title)
    ok(f"title set: {title}")
    _state["stats"]["retitled"] = True
    return True


def _blade_bio(client, guid, kind, bio):
    """◼ blade two — rewrite the description (max 300 chars)."""
    bio = (bio or "").strip()
    if not bio:
        return False
    if len(bio) > 300:
        warn(f"bio exceeds Rubika's 300-char limit — truncating ({len(bio)})")
        bio = bio[:300]
    if _state["dry_run"]:
        warn(f"DRY RUN — would rewrite bio to: {bio[:60]}")
        return True
    _o(f"rewriting bio → {_OX.EDGE}{bio[:60]}{'…' if len(bio) > 60 else ''}{_OX.RESET}")
    if kind == "group":
        client.edit_group_info(guid, description=bio)
    else:
        client.edit_channel_info(guid, description=bio)
    ok("bio rewritten")
    _state["stats"]["rebioed"] = True
    return True


def _blade_avatar(client, guid, avatar_path, wipe):
    """◼ blade three — wipe stored avatars, upload the new one."""
    if not avatar_path:
        return False
    if not os.path.exists(avatar_path):
        err(f"avatar file not found: {avatar_path}")
        return False

    if _state["dry_run"]:
        warn(f"DRY RUN — would wipe avatars + upload {os.path.basename(avatar_path)}")
        return True
    try:
        current = _get(_state["client"].get_avatars(guid), "avatars") or []
        _state["stats"]["avatars_old"] = len(list(current))
    except Exception:
        pass
    if wipe:
        try:
            client.delete_all_avatars(guid)
            ok("all stored avatars wiped")
        except Exception as e:
            _o(f"{_OX.ASH}ℹ avatar wipe skipped — {e}")

    client.upload_avatar(guid, main_image=avatar_path)
    ok(f"avatar uploaded: {os.path.basename(avatar_path)}")
    _state["stats"]["avatars_new"] += 1
    return True


def _blade_purge(client, guid, kind, self_guid, admin_guids):
    """
    ◼ blade four — the purge.
    Bans EVERY member of the chat EXCEPT:
      · admins / creator            (protect_admins)
      · bots                        (protect_bots)
      · the session account itself
    """
    s = _state["stats"]
    s["admins"] = len(admin_guids)

    _o(f"reading every member of the {_kind_label(kind)}…")
    members = _fetch_all_members(client, guid, kind)
    s["members"] = len(members)

    condemned = []
    for m in members:
        g = _member_guid(m)
        if not g or g == guid:
            continue
        if g == self_guid:
            continue
        if _state["protect_admins"] and g in admin_guids:
            continue
        if _state["protect_admins"] and g[:2].lower() == "s0":  # creator-type guids ride with admins
            continue
        if _state["protect_bots"] and g[:2].lower() == "b0":
            s["bots"] += 1
            continue
        condemned.append(g)

    _o(
        f"PURGE LIST — {_OX.BLOOD}{len(condemned)}{_OX.RESET} of {s['members']} members "
        f"(admins spared: {s['admins']}, bots spared: {s['bots']})"
    )
    if not condemned:
        ok("nothing to purge — the chat is already clean")
        return

    if _state["dry_run"]:
        warn("DRY RUN — no bans sent. set dry_run false (or command 'real') to commit.")
        return

    chunk_size = max(1, _state["ban_chunk"])
    total = (len(condemned) + chunk_size - 1) // chunk_size
    for i in range(0, len(condemned), chunk_size):
        if _state["stop"]:
            _o(f"{_OX.ASH}⏹ purge stopped by operator")
            return
        chunk = condemned[i:i + chunk_size]
        n = i // chunk_size + 1
        try:
            client.ban_members(guid, members=chunk)
            s["banned"] += len(chunk)
            _o(f"proscribed {n}/{total} — {_OX.BLOOD}{len(chunk)}{_OX.RESET} member(s) banned")
            if n < total:
                _sleep(_state["ban_delay"])
        except Exception as e:
            s["ban_failed"] += len(chunk)
            _o(f"{_OX.BLOOD}✗✗{_OX.RESET} chunk {n} failed — {e}")
            if "TOO_REQUESTS" in str(e) or "rate" in str(e).lower():
                _o(f"{_OX.BLOOD}🛑 rate limit — purge halting")
                _state["stop"] = True
                return


def _unban_wave(client, guid):
    """◼ mercy — lift every ban on the chat."""
    if _state["dry_run"]:
        warn("DRY RUN — would lift every ban on the target")
        return
    _o("lifting every ban on the target…")
    try:
        client.unban_all_members(guid)
        ok("all bans lifted — the chat is open again")
        _state["stats"]["unbanned"] += 1
    except Exception as e:
        err(f"unban failed — {e}")


# ──────────────────────────────────────────────────────────────────────────────
#  Worker — one full engage pass
# ──────────────────────────────────────────────────────────────────────────────
def _engage_worker(client, target, self_guid=None):
    if _state["engaging"]:
        warn("an engage pass is already running")
        return
    _state["engaging"] = True
    _state["stop"] = False
    s = _state["stats"]
    for key in ("kind", "guid", "members", "admins", "bots", "banned",
                "ban_failed", "unbanned", "retitled", "rebioed",
                "avatars_old", "avatars_new"):
        s[key] = False if key in ("retitled", "rebioed") else (None if key == "kind" else 0)
    s["started_at"] = time.time()

    try:
        if _state["dry_run"]:
            _o(f"{_OX.ASH}dry run active — this pass touches nothing")
        _o(f"{_OX.EDGE}{_OX.BOLD}◼ OBSIDIAN VANGUARD — engage{_OX.RESET}")
        _o(TAGLINE)

        guid, kind = _resolve_target(client, target)
        if not guid:
            return
        s["guid"], s["kind"] = guid, kind
        _o(f"target locked: {_kind_label(kind)} {_OX.EDGE}{guid}{_OX.RESET}")

        admin_guids = _fetch_admin_guids(client, guid, kind) if _state["protect_admins"] else set()

        blades = []
        if _state["new_name"]:
            blades.append("retitle")
        if _state["new_bio"]:
            blades.append("re-bio")
        if _state["avatar"]:
            blades.append("avatar")
        if _state["ban_all"]:
            blades.append("purge")
        if _state["unban_after"]:
            blades.append("unban")
        _o(f"blades drawn: {_OX.EDGE}{', '.join(blades) or 'none'}{_OX.RESET}")

        try:
            _blade_title(client, guid, kind, _state["new_name"])
        except Exception as e:
            err(f"retitle failed — {e}")
        try:
            _blade_bio(client, guid, kind, _state["new_bio"])
        except Exception as e:
            err(f"re-bio failed — {e}")
        try:
            _blade_avatar(client, guid, _state["avatar"], _state["wipe_avatars"])
        except Exception as e:
            err(f"avatar pass failed — {e}")

        if _state["ban_all"]:
            try:
                _blade_purge(client, guid, kind, self_guid, admin_guids)
            except Exception as e:
                err(f"purge failed — {e}")

        if _state["unban_after"]:
            _unban_wave(client, guid)

    finally:
        _state["engaging"] = False
        elapsed = (time.time() - s["started_at"]) if s["started_at"] else 0
        _o(
            f"{_OX.VIOLET}◼ engage report{_OX.RESET} — retitled={s['retitled']} "
            f"rebioed={s['rebioed']} avatars_old={s['avatars_old']} avatars_new={s['avatars_new']} "
            f"members={s['members']} banned={s['banned']} failed={s['ban_failed']} "
            f"admins={s['admins']} bots={s['bots']} time={elapsed:.1f}s"
        )


# ──────────────────────────────────────────────────────────────────────────────
#  Subshell ops
# ──────────────────────────────────────────────────────────────────────────────
def _prompt_fn():
    s = _state["stats"]
    flag = "▶" if _state["engaging"] else "◼"
    mode = "DRY" if _state["dry_run"] else "LIVE"
    color = _OX.ASH if _state["dry_run"] else _OX.BLOOD
    return (
        f"  {_OX.VIOLET}ssghost{_OX.RESET} {_OX.ASH}{flag}{_OX.RESET} "
        f"{color}{mode}{_OX.RESET} {_OX.ASH}{s['banned']}b/{s['ban_failed']}f{_OX.RESET} ⚔ {_OX.RESET}"
    )


def _completer(text, line, begidx, endidx):
    cmds = [
        "target", "engage", "real", "rebrand", "unban", "banned", "admins",
        "status", "log", "stop", "help",
    ]
    return [c for c in cmds if c.startswith(text)]


def _subshell_handler(line):
    line = line.strip()
    parts = line.split(maxsplit=1)
    if not parts:
        return
    cmd = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""
    s = _state["stats"]

    if cmd == "target":
        if not arg:
            _o("usage: target <GROUP|CHANNEL guid|link|username>")
            return
        guid, kind = _resolve_target(_state["client"], arg) if _state["client"] else (None, None)
        if guid is None and _state["client"] is not None:
            return
        _state["target"] = arg
        ok(f"target set → {arg}")

    elif cmd == "engage":
        if not _state["target"]:
            err("no target — use: target <guid|link|username>")
            return
        threading.Thread(
            target=_engage_worker,
            args=(_state["client"], _state["target"]),
            daemon=True,
            name="ssghost-engage",
        ).start()

    elif cmd == "real":
        if _state["engaging"]:
            warn("an engage pass is running — finish it first")
            return
        _state["dry_run"] = False
        warn("LIVE MODE — next 'engage' sends real API calls (bans are irreversible)")

    elif cmd == "rebrand":
        if not _state["target"]:
            err("no target — use: target <guid|link|username>")
            return
        if _state["engaging"]:
            warn("an engage pass is already running")
            return
        keep_dry = _state["dry_run"]
        _state["dry_run"] = False
        t, b, a, ban = _state["new_name"], _state["new_bio"], _state["avatar"], _state["ban_all"]
        _state["ban_all"] = False
        _state["unban_after"] = False
        threading.Thread(
            target=_engage_worker,
            args=(_state["client"], _state["target"]),
            daemon=True,
            name="ssghost-rebrand",
        ).start()
        _state["dry_run"] = keep_dry or False
        _state["ban_all"] = ban
        if not (t or b or a):
            warn("rebrand called but new_name / new_bio / avatar are all empty")

    elif cmd == "unban":
        if not _state["target"]:
            err("no target — use: target <guid|link|username>")
            return
        if _state["dry_run"]:
            warn("DRY RUN — unban skipped; run 'real' first")
            return
        threading.Thread(
            target=_unban_threaded,
            args=(_state["client"], _state["target"]),
            daemon=True,
            name="ssghost-unban",
        ).start()

    elif cmd == "banned":
        if not _state["target"]:
            err("no target — use: target <guid|link|username>")
            return
        try:
            resp = _state["client"].get_banned_members(_state["target"], show_member_guids=True)
            guids = list(_get(resp, "member_guids") or [])
            _o(f"banned members: {_OX.BLOOD}{len(guids)}{_OX.RESET}")
            for g in guids[:30]:
                print(f"      {_OX.ASH}{g}{_OX.RESET}")
        except Exception as e:
            err(f"get_banned_members failed — {e}")

    elif cmd == "admins":
        if not _state["target"]:
            err("no target — use: target <guid|link|username>")
            return
        guid, kind = _resolve_target(_state["client"], _state["target"])
        if not guid:
            return
        admins = _fetch_admin_guids(_state["client"], guid, kind)
        _o(f"admins ({_OX.LIVE}{len(admins)}{_OX.RESET}) — these are never purged:")
        for g in list(admins)[:30]:
            print(f"      {_OX.LIVE}{g}{_OX.RESET}")

    elif cmd == "status":
        elapsed = (time.time() - s["started_at"]) if s["started_at"] else 0
        print(f"\n  {_OX.VIOLET}╔══{"═" * 53}╗{_OX.RESET}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  {_OX.EDGE}{_OX.BOLD}OBSIDIAN VANGUARD — ssghost status{_OX.RESET}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  listener     : {_OX.LIVE + 'ONLINE' if _state['running'] else _OX.BLOOD + 'OFFLINE'}{_OX.RESET}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  engaging     : {_OX.LIVE + 'YES' if _state['engaging'] else _OX.ASH + 'no'}{_OX.RESET}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  mode         : "
              f"{_OX.BLOOD + 'LIVE' if not _state['dry_run'] else _OX.ASH + 'DRY RUN'}{_OX.RESET}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  target       : {_OX.EDGE}{_state['target'] or '—'}{_OX.RESET}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  new_name     : {_state['new_name'] or '—'}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  new_bio      : {(_state['new_bio'][:40] + '…') if len(_state['new_bio']) > 40 else (_state['new_bio'] or '—')}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  avatar       : {_state['avatar'] or '—'}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  ban_all      : {_OX.LIVE if _state['ban_all'] else _OX.ASH}{_state['ban_all']}{_OX.RESET}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  protect      : admins={_state['protect_admins']} bots={_state['protect_bots']}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  unban_after  : {_state['unban_after']}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  members      : {s['members']}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  banned       : {_OX.BLOOD}{s['banned']}{_OX.RESET}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  ban_failed   : {s['ban_failed']}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  admins spared: {s['admins']}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  bots spared  : {s['bots']}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  elapsed      : {elapsed:.1f}s")
        print(f"  {_OX.VIOLET}╚══{"═" * 53}╝{_OX.RESET}\n")

    elif cmd == "log":
        if not _state["log"]:
            print(f"    {_OX.ASH}(empty){_OX.RESET}")
            return
        for e in _state["log"][-40:]:
            print(f"    {e}")

    elif cmd == "stop":
        _state["stop"] = True
        _o("stop requested")

    elif cmd in ("help", "?"):
        print(f"""
  {_OX.VIOLET}◼{_OX.RESET} {_OX.EDGE}ssghost — OBSIDIAN VANGUARD command deck{_OX.RESET}
    {_OX.VIOLET}target <id>{_OX.RESET}    point the blade (group OR channel: guid/link/username)
    {_OX.VIOLET}engage{_OX.RESET}         full pass — retitle + bio + avatar + purge + unban (per options)
    {_OX.VIOLET}rebrand{_OX.RESET}        identity only — retitle + bio + avatar, no bans
    {_OX.VIOLET}real{_OX.RESET}           go LIVE (leaves dry-run; bans become irreversible)
    {_OX.VIOLET}unban{_OX.RESET}          lift every ban on the target
    {_OX.VIOLET}banned{_OX.RESET}         list banned members
    {_OX.VIOLET}admins{_OX.RESET}         list the untouchables (admins/creator)
    {_OX.VIOLET}status{_OX.RESET}         live board
    {_OX.VIOLET}log{_OX.RESET}            tail the last 40 lines
    {_OX.VIOLET}stop{_OX.RESET}           abort the running pass
    {_OX.VIOLET}back/exit{_OX.RESET}      leave this deck

  {_OX.ASH}dry run is {'ON — engage simulates everything' if _state['dry_run'] else 'OFF — engage sends real API calls'}{_OX.RESET}
""")
    else:
        print(f"    {_OX.BLOOD}unknown{_OX.RESET}: {cmd} — try 'help'")


def _unban_threaded(client, target):
    guid, kind = _resolve_target(client, target)
    if guid:
        _unban_wave(client, guid)


def _on_exit():
    _state["stop"] = True
    _state["running"] = False
    _state["client"] = None
    _state["app_thread"] = None


# ──────────────────────────────────────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────────────────────────────────────
def run(opts):
    if _state["running"]:
        warn("ssghost is already running")
        return

    try:
        from maxrubika import Messenger
    except ImportError:
        err(f"[{NAME}] maxrubika is not installed — pip install maxrubika")
        return

    session = str(opts.get("session") or "mySession")
    trigger = str(opts.get("trigger") or "/ssghost")

    def num(k, default, cast=float):
        try:
            return cast(opts.get(k, default))
        except (TypeError, ValueError):
            return default

    _state.update({
        "running":        True,
        "engaging":       False,
        "stop":           False,
        "trigger":        trigger,
        "target":         str(opts.get("target") or OPTIONS["target"]["value"] or "").strip(),
        "new_name":       str(opts.get("new_name") or "").strip(),
        "new_bio":        str(opts.get("new_bio") or "").strip(),
        "avatar":         str(opts.get("avatar") or "").strip(),
        "wipe_avatars":   bool(opts.get("wipe_avatars", True)),
        "ban_all":        bool(opts.get("ban_all", True)),
        "protect_admins": bool(opts.get("protect_admins", True)),
        "protect_bots":   bool(opts.get("protect_bots", True)),
        "ban_chunk":      max(1, num("ban_chunk", 10, int)),
        "ban_delay":      max(0.0, num("ban_delay", 2.0)),
        "unban_after":    bool(opts.get("unban_after", False)),
        "dry_run":        bool(opts.get("dry_run", True)),
        "stats": {
            "kind": None, "guid": None, "members": 0, "admins": 0, "bots": 0,
            "banned": 0, "ban_failed": 0, "unbanned": 0,
            "retitled": False, "rebioed": False,
            "avatars_old": 0, "avatars_new": 0, "started_at": None,
        },
        "log": [],
    })

    if _state["dry_run"]:
        warn("DRY RUN is ON — engage simulates everything and sends nothing")

    try:
        app = Messenger(session)
    except Exception as e:
        err(f"client init failed: {e}")
        _state["running"] = False
        return

    _state["client"] = app

    # ── in-chat trigger — engage the chat the command was sent in ────────────
    @app.on_new_message()
    async def _handler(event):
        if not _state["running"]:
            return
        try:
            text = event.text
        except AttributeError:
            return
        if not text or text.strip() != _state["trigger"]:
            return

        chat = None
        for attr in ("chat_guid", "group_guid", "channel_guid", "object_guid"):
            chat = getattr(event, attr, None)
            if chat:
                break
        if not chat:
            _o("⚠ could not detect the chat id from the event")
            return
        if _kind_from_guid(chat) not in ("group", "channel"):
            _o(f"⚠ the trigger must be sent inside a group or channel (got {chat})")
            return
        if _state["engaging"]:
            warn("an engage pass is already running")
            return

        self_guid = getattr(event, "author_guid", None)
        _o(f"{_OX.EDGE}trigger '{_state['trigger']}' received — engaging {chat}{_OX.RESET}")
        threading.Thread(
            target=_engage_worker,
            args=(app, chat, self_guid),
            daemon=True,
            name="ssghost-engage",
        ).start()

    # ── background listener ───────────────────────────────────────────────────
    _state["app_thread"] = threading.Thread(
        target=app.run,
        daemon=True,
        name="ssghost-listener",
    )
    _state["app_thread"].start()

    # ── Obsidian Vanguard boot splash ─────────────────────────────────────────
    print(f"{_OX.VIOLET}{BANNER}{_OX.RESET}")
    print(f"  {_OX.VIOLET}◼{_OX.RESET} {_OX.EDGE}{TAGLINE}{_OX.RESET}")
    print(f"  {_OX.VIOLET}◼{_OX.RESET} session       : {session}")
    print(f"  {_OX.VIOLET}◼{_OX.RESET} trigger       : {_OX.EDGE}{trigger}{_OX.RESET}  (send this inside any group/channel you administer)")
    print(f"  {_OX.VIOLET}◼{_OX.RESET} target        : {_state['target'] or '(not set — use: target <id>)'}")
    print(f"  {_OX.VIOLET}◼{_OX.RESET} blades        : "
          f"{('retitle' if _state['new_name'] else '')}"
          f"{' +bio' if _state['new_bio'] else ''}"
          f"{' +avatar' if _state['avatar'] else ''}"
          f"{' +purge' if _state['ban_all'] else ''}"
          f"{' +unban' if _state['unban_after'] else ''}"
          f"{' — (all idle: set new_name/new_bio/avatar in options)' if not (_state['new_name'] or _state['new_bio'] or _state['avatar'] or _state['ban_all']) else ''}")
    print(f"  {_OX.VIOLET}◼{_OX.RESET} mode          : "
          f"{_OX.BLOOD + 'LIVE' if not _state['dry_run'] else _OX.ASH + 'DRY RUN'}{_OX.RESET}")
    print(f"  {_OX.VIOLET}◼{_OX.RESET} protect       : admins={_state['protect_admins']} · bots={_state['protect_bots']}")
    print(f"  {_OX.VIOLET}◼{_OX.RESET} type {_OX.EDGE}help{_OX.RESET} in the subshell\n")

    shell = globals().get("EIDOLON_SHELL")
    if shell is not None and hasattr(shell, "enter_subshell"):
        shell.enter_subshell(
            handler=_subshell_handler,
            completer=_completer,
            prompt_fn=_prompt_fn,
            on_exit=_on_exit,
        )
        return

    try:
        while _state["running"]:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        _on_exit()
