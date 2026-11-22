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
  ◼  waves          the purge re-reads the member list after every
                     wave (default: unlimited) — banned members drop
                     out, so it keeps sweeping until nothing is left,
                     no matter the chat size
  ◼  quiet mode     silence group event messages for the duration
                     of the pass, restore them afterwards     (edit_group_info event_messages)
  ◼  profiles       forge identities (title + bio + avatar + every
                     granular chat setting) into a local vault and
                     apply them by name
  ◼  settings       fine-tune every editable section of the chat:
                     slow mode, reactions, restricted content
                     (on by default), channel privacy — 'P' privates
                     the channel, any other name becomes the public
                     username with a random 3-4 digit code appended —
                     and signed posts (off by default); every field
                     is attempted on its own, a refusal never stops
                     the pass

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
    chunk <N> / settings          ban batch size / show every pending setting
    quiet on|off                  silence group event messages during passes
    profile / profile save <n>    identity vault: list / forge (title+bio+avatar)
    profile <n> / profile del <n> apply now / shatter a saved profile
    status / log / stop           live ops

In-chat: send the `trigger` inside any group or channel you administer
to engage the full pass on that chat:
    `/ssghost`                full pass with the current options
    `/ssghost <profile>`      identity-only pass with that saved profile
With trigger_requires_self on (default), only the session's own
account can fire the trigger.

⚠  This module crashes communities by design. It only works on chats
   where the session holds admin/creator rights — Rubika enforces
   that server-side. Point it only at chats you own or administer.
"""

import json
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
  ◼     ◼ ◼   ◼  ◼◼◼◼   ◼     ◼  ◼     ◼     ssghost · v3.2.1
  ◼     ◼  ◼ ◼   ◼      ◼     ◼   ◼   ◼      forged in pressure
   ◼◼◼◼     ◼    ◼◼◼◼◼   ◼◼◼◼      ◼◼◼       first to engage
"""

TAGLINE = "Forged in pressure. Sharpened in silence. First to engage."

# ──────────────────────────────────────────────────────────────────────────────
#  Module metadata
# ──────────────────────────────────────────────────────────────────────────────
NAME        = "ssghost"
VERSION     = "3.3.1"
DESCRIPTION = "OBSIDIAN VANGUARD official — rebrand a Rubika group/channel (title/bio/avatar, savable profiles that also carry every granular chat setting), silence event messages during the pass, and purge every member in unlimited waves (admins & bots exempt, smart granular settings) via maxrubika"
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
    "slow_mode": {
        "value":    "",
        "required": False,
        "desc":     "group only: slow mode between messages, in seconds (empty = untouched)",
    },
    "reactions": {
        "value":    "",
        "required": False,
        "desc":     "group only: reactions setting — All / Disable / comma-separated ids (empty = untouched)",
    },
    "restricted_content": {
        "value":    "on",
        "required": False,
        "desc":     "group & channel, default 'on': is_restricted_content blocks screenshots and file saving — 'on' enables, 'off' disables, 'skip' = untouched; applied on its own, a refused field never stops the pass",
    },
    "sign_messages": {
        "value":    "off",
        "required": False,
        "desc":     "channel only, default 'off': sign every post with the channel name — 'off' disables signing, 'on' enables, 'skip' = untouched; applied on its own, a refused field never stops the pass",
    },
    "chat_username": {
        "value":    "",
        "required": False,
        "desc":     "channel only, one smart field: 'P' = switch the channel to Private; any other text = public username base — a random 3-4 digit code is appended and applied (e.g. 'Ghost_union' -> 'Ghost_union734', max 32 chars); empty = untouched",
    },
    "quiet_mode": {
        "value":    True,
        "required": False,
        "desc":     "groups only, default ON: silence event messages during the pass via edit_group_info(event_messages=False), restore True afterwards; if the session lacks the permission the pass continues without it",
    },
    "profile": {
        "value":    "",
        "required": False,
        "desc":     "name of a saved profile (title + bio + avatar + granular chat settings) from the vault, armed at boot when the module is launched with options; save/apply/manage profiles with the subshell 'profile' verb",
    },
    "trigger_requires_self": {
        "value":    True,
        "required": False,
        "desc":     "the in-chat trigger only fires when the session's own account sends it",
    },
    "unban_after": {
        "value":    True,
        "required": False,
        "desc":     "after the pass, lift every ban via unban_all_members (default ON — bans should not stick to the account)",
    },
    "dry_run": {
        "value":    False,
        "required": False,
        "desc":     "simulate everything: show exactly what would happen, send nothing (default OFF — engage is LIVE; set True for a rehearsal pass)",
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
    "slow_mode":      "",
    "reactions":      "",
    "restricted_content": "on",
    "sign_messages":  "off",
    "chat_username":  "",
    "quiet_mode":     True,
    "trigger_requires_self": True,
    "self_guid":      None,
    "profile":        "",
    "unban_after":    True,
    "dry_run":        False,
    "stats": {
        "kind":        None,   # group | channel
        "guid":        None,
        "members":     0,
        "scanned":     0,
        "rounds":      0,
        "quiet":       None,
        "admins":      0,
        "bots":        0,
        "banned":      0,
        "ban_failed":  0,
        "unbanned":    0,
        "settings_ok": 0,
        "settings_failed": 0,
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


# ─────────────────────────────────────────────────────────────────────────────
#  Profile vault — named identities (title + bio + avatar + every granular chat setting) persisted on disk
# ─────────────────────────────────────────────────────────────────────────────
PROFILE_VAULT = os.path.join(os.path.expanduser("~"), ".eidolon", "ssghost_profiles.json")


def _load_profiles():
    try:
        with open(PROFILE_VAULT, "r", encoding="utf-8") as f:
            data = json.load(f)
        return dict(data) if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        _o(f"{_OX.ASH}ℹ profile vault unreadable ({e}) — starting empty{_OX.RESET}")
        return {}


def _save_profiles(profiles):
    os.makedirs(os.path.dirname(PROFILE_VAULT), exist_ok=True)
    with open(PROFILE_VAULT, "w", encoding="utf-8") as f:
        json.dump(profiles, f, ensure_ascii=False, indent=2)


PROFILE_FIELDS = {
    "name":              "new_name",
    "bio":               "new_bio",
    "avatar":            "avatar",
    "slow_mode":         "slow_mode",
    "reactions":         "reactions",
    "restricted_content": "restricted_content",
    "sign_messages":     "sign_messages",
    "chat_username":     "chat_username",
}


def _apply_profile(name):
    """Pull a saved identity into every live slot it carries (old vaults
    with title/bio/avatar only keep working — missing keys are left as-is)."""
    prof = _load_profiles().get(name)
    if not isinstance(prof, dict):
        return False
    for record_key, state_key in PROFILE_FIELDS.items():
        if record_key in prof:
            _state[state_key] = str(_get(prof, record_key) or "")
    return True


def _parse_trigger(raw):
    """Message text → (is_trigger, profile_name_or_'')."""
    stripped = (raw or "").strip()
    trig = _state["trigger"]
    if stripped == trig:
        return True, ""
    if stripped.startswith(trig + " "):
        return True, stripped[len(trig):].strip()
    return False, ""


def _profile_engage_thread(client, target, name, keep):
    if not _apply_profile(name):
        err(f"profile '{name}' vanished from the vault")
        return
    try:
        _engage_worker(client, target, _state.get("self_guid"))
    finally:
        _state["ban_all"], _state["unban_after"], _state["dry_run"] = keep


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
    avatar_path = _avatar_path(avatar_path)
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


def _avatar_path(p):
    """Operator input → real path: surrounding quotes off, ~ expanded."""
    return os.path.expanduser(str(p or "").strip().strip("'\"").strip())


def _tri_state(raw):
    """Operator input → 'on' / 'off' / 'skip' (untouched)."""
    s = str(raw or "").strip().lower()
    if s in ("on", "true", "1", "yes"):
        return "on"
    if s in ("off", "false", "0", "no"):
        return "off"
    return "skip"


def _username_code(base):
    """Public-username base → base + a random 3-4 digit code, capped at 32 chars."""
    n = random.choice((3, 4))
    code = str(random.randint(10 ** (n - 1), 10 ** n - 1))
    room = 32 - len(code)
    return base[:room] + code


def _blade_settings(client, guid, kind):
    """
    ▸ blade — every editable section of the chat, field by field.
    Each field is applied on its own: a refused setting is logged and the pass
    moves on — nothing dies because one permission is missing.
    """
    s = _state["stats"]

    def apply(what, fn):
        if _state["dry_run"]:
            warn(f"DRY RUN — would set {what}")
            return
        try:
            fn()
            ok(f"set {what}")
            s["settings_ok"] += 1
        except Exception as e:
            err(f"{what} refused — passing without it ({e})")
            s["settings_failed"] += 1

    restricted = _tri_state(_state["restricted_content"])
    if kind == "group":
        mode = str(_state["slow_mode"]).strip()
        if mode:
            if not mode.isdigit():
                warn("slow_mode must be seconds (digits) — skipped")
            else:
                apply(f"slow_mode={mode}s", lambda: client.edit_group_info(guid, slow_mode=mode))
        rx = str(_state["reactions"]).strip()
        if rx:
            if rx in ("All", "Disable"):
                apply(f"reactions={rx}", lambda: client.edit_group_info(guid, reactions=rx))
            elif all(x.strip().isdigit() for x in rx.split(",")):
                ids = [int(x) for x in rx.split(",") if x.strip().isdigit()]
                apply(f"reactions=ids:{rx}", lambda: client.edit_group_info(guid, reactions=ids))
            else:
                warn("reactions must be All / Disable / comma-separated ids — skipped")
        if restricted != "skip":
            apply(f"is_restricted_content={restricted}",
                  lambda: client.edit_group_info(guid, is_restricted_content=(restricted == "on")))
    else:
        raw = str(_state["chat_username"]).strip().lstrip("@")
        if raw.lower() == "p":
            apply("channel_type=Private", lambda: client.edit_channel_info(guid, channel_type="Private"))
        elif raw:
            if not all(ch.isalnum() or ch == "_" for ch in raw):
                warn("username may only contain letters, digits and '_' — skipped")
            else:
                user = _username_code(raw)
                apply(f"username={user}", lambda: client.edit_channel_info(guid, username=user))
        sign = _tri_state(_state["sign_messages"])
        if sign != "skip":
            apply(f"sign_messages={sign}", lambda: client.edit_channel_info(guid, sign_messages=(sign == "on")))
        if restricted != "skip":
            apply(f"is_restricted_content={restricted}",
                  lambda: client.edit_channel_info(guid, is_restricted_content=(restricted == "on")))


def _purge_round(client, guid, kind, self_guid, admin_guids, round_no, total_rounds, seen):
    """▸ wave — fetch, filter, ban. Returns how many were banned this round."""
    s = _state["stats"]
    if total_rounds == 1:
        label = "the purge"
    else:
        label = f"purge wave {round_no}/{'∞' if total_rounds == 0 else total_rounds}"
    _o(f"reading every member of the {_kind_label(kind)} — {label}…")
    members = _fetch_all_members(client, guid, kind)
    s["members"] = len(members)
    s["scanned"] += len(members)

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

    fresh = [g for g in condemned if g not in seen]
    seen.update(condemned)

    _o(
        f"PURGE LIST — {_OX.BLOOD}{len(fresh)}{_OX.RESET} of {s['members']} members "
        f"(admins spared: {s['admins']}, bots spared: {s['bots']})"
    )
    if condemned and not fresh:
        ok("every listed member is already proscribed — waves complete")
        return 0
    if not condemned:
        ok("nothing left to purge — the chat is clean")
        return 0

    if _state["dry_run"]:
        warn("DRY RUN — no bans sent. set dry_run false (or command 'real') to commit.")
        return 0

    before = s["banned"]
    chunk_size = max(1, _state["ban_chunk"])
    total = (len(fresh) + chunk_size - 1) // chunk_size
    for i in range(0, len(fresh), chunk_size):
        if _state["stop"]:
            _o(f"{_OX.ASH}⏹ purge stopped by operator")
            break
        chunk = fresh[i:i + chunk_size]
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
                break
    return s["banned"] - before


def _blade_purge(client, guid, kind, self_guid, admin_guids):
    """
    ▣ blade four — the purge, in waves.
    Every member of the chat is banned EXCEPT: admins/creator (protect_admins),
    bots (protect_bots) and the session account itself. Each wave re-reads the
    member list — banned members drop out of it, so the next wave reaches past
    Rubika's ~100-member fetch window on large chats. The waves are permanently
    unlimited: they run until the purge list is empty, whatever the chat size.
    Loops terminate on: empty purge list, no new targets left (fuse), 'stop',
    dry run, or a rate limit.
    """
    s = _state["stats"]
    s["admins"] = len(admin_guids)
    seen = set()
    wave = 0
    while True:
        if _state["stop"]:
            _o(f"{_OX.ASH}⏹ purge stopped by operator")
            break
        if wave >= 1000:
            warn("safety fuse hit after 1000 waves — stopping (should never reach here)")
            break
        wave += 1
        s["rounds"] = wave
        if _purge_round(client, guid, kind, self_guid, admin_guids, wave, 0, seen) <= 0:
            break
        _o(f"wave {wave} spent — rescanning what is left…")
        _sleep(1.0)


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
    for key in ("kind", "guid", "members", "scanned", "rounds", "admins", "bots", "banned",
                "ban_failed", "unbanned", "quiet", "settings_ok", "settings_failed",
                "retitled", "rebioed", "avatars_old", "avatars_new"):
        s[key] = False if key in ("retitled", "rebioed") else (
            None if key in ("kind", "quiet") else 0
        )
    s["started_at"] = time.time()
    self_guid = self_guid or _state.get("self_guid")

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
        if any((_state["slow_mode"], _state["reactions"], _state["chat_username"],
                _tri_state(_state["restricted_content"]) != "skip",
                _tri_state(_state["sign_messages"]) != "skip")):
            blades.append("settings")
        if _state["ban_all"]:
            blades.append("purge")
        if _state["unban_after"]:
            blades.append("unban")
        if _state["quiet_mode"]:
            blades.append("quiet")
        _o(f"blades drawn: {_OX.EDGE}{', '.join(blades) or 'none'}{_OX.RESET}")

        if _state["quiet_mode"]:
            if _state["dry_run"]:
                warn("DRY RUN — would silence group event messages for the pass")
            elif kind == "group":
                try:
                    client.edit_group_info(guid, event_messages=False)
                    s["quiet"] = "off"
                    _o(f"{_OX.ASH}ℹ event messages silenced for the duration of the pass{_OX.RESET}")
                except Exception as e:
                    _o(f"{_OX.ASH}ℹ could not silence event messages — {e}{_OX.RESET}")
            else:
                _o(f"{_OX.ASH}ℹ event messages are a group setting — nothing to silence on a channel{_OX.RESET}")

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
        try:
            _blade_settings(client, guid, kind)
        except Exception as e:
            err(f"settings pass failed — {e}")

        if _state["ban_all"]:
            try:
                _blade_purge(client, guid, kind, self_guid, admin_guids)
            except Exception as e:
                err(f"purge failed — {e}")

        if _state["unban_after"]:
            _unban_wave(client, guid)

    finally:
        if s.get("quiet") == "off" and s.get("guid"):
            try:
                client.edit_group_info(s["guid"], event_messages=True)
                s["quiet"] = "restored"
                _o(f"{_OX.ASH}ℹ event messages restored{_OX.RESET}")
            except Exception as e:
                s["quiet"] = "restore-failed"
                _o(f"{_OX.BLOOD}✗✗{_OX.RESET} event-messages restore failed — {e}")
        _state["engaging"] = False
        elapsed = (time.time() - s["started_at"]) if s["started_at"] else 0
        _o(
            f"{_OX.VIOLET}◼ engage report{_OX.RESET} — retitled={s['retitled']} "
            f"rebioed={s['rebioed']} avatars_old={s['avatars_old']} avatars_new={s['avatars_new']} "
            f"members={s['members']} scanned={s['scanned']} waves={s['rounds']} banned={s['banned']} failed={s['ban_failed']} "
            f"settings_ok={s['settings_ok']} settings_failed={s['settings_failed']} "
            f"admins={s['admins']} bots={s['bots']} time={elapsed:.1f}s"
        )


# ──────────────────────────────────────────────────────────────────────────────
#  Subshell ops
# ──────────────────────────────────────────────────────────────────────────────
def _profiles_cmd(arg):
    store = _load_profiles()
    parts = arg.split(maxsplit=1)
    sub = (parts[0] or "").lower() if parts else ""
    rest = parts[1].strip() if len(parts) > 1 else ""

    if sub == "save":
        if not rest:
            err("usage: profile save <name>")
            return
        armed = {k: _state[sk] for k, sk in PROFILE_FIELDS.items() if _state[sk]}
        if not armed:
            err("nothing armed — set new_name / new_bio / avatar / slow_mode / reactions / restricted_content / sign_messages / chat_username first (or load one: profile <name>)")
            return
        store[rest] = armed
        try:
            _save_profiles(store)
        except Exception as e:
            err(f"profile save failed — {e}")
            return
        ok(f"profile '{rest}' forged ({len(armed)} fields) → {PROFILE_VAULT}")
    elif sub in ("del", "rm", "delete"):
        if not rest or rest not in store:
            err(f"no profile named '{rest}'")
            return
        del store[rest]
        try:
            _save_profiles(store)
        except Exception as e:
            err(f"profile delete failed — {e}")
            return
        ok(f"profile '{rest}' shattered")
    elif sub in ("list", "ls") or not sub:
        if not store:
            _o(f"{_OX.ASH}ℹ vault empty — forge one: profile save <name>  ({PROFILE_VAULT})")
            return
        _o(f"profile vault ({_OX.VIOLET}{len(store)}{_OX.RESET}) → {PROFILE_VAULT}")
        for pname, prof in store.items():
            name = _get(prof, "name") or "—"
            bio = str(_get(prof, "bio") or "—")
            av = str(_get(prof, "avatar") or "—")
            extras = [f"{k}={_get(prof, k)}" for k in PROFILE_FIELDS if k not in ("name", "bio", "avatar") and _get(prof, k)]
            extra_s = f" · {' · '.join(extras)}" if extras else ""
            print(f"      {_OX.EDGE}{pname}{_OX.RESET} · title={name} · bio={bio[:40]} · avatar={os.path.basename(av)}{extra_s}")
    else:
        name = arg.strip()
        if not _apply_profile(name):
            err(f"no profile named '{name}' — 'profile save {name}' forges it")
            return
        ok(f"profile '{name}' loaded → armed: {' + '.join(k for k, sk in PROFILE_FIELDS.items() if _state[sk]) or 'nothing'}")
        if _state["target"] and not _state["engaging"]:
            keep = (_state["ban_all"], _state["unban_after"], _state["dry_run"])
            _state["ban_all"] = False
            _state["unban_after"] = False
            _state["dry_run"] = False
            warn(f"LIVE identity pass — profile '{name}' on {_state['target']}")
            threading.Thread(
                target=_profile_engage_thread,
                args=(_state["client"], _state["target"], name, keep),
                daemon=True,
                name="ssghost-profile",
            ).start()
        else:
            _o(f"{_OX.ASH}ℹ profile '{name}' armed — set a target, or send '{_state['trigger']} {name}' in-chat{_OX.RESET}")


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
        "target", "engage", "real", "rebrand", "profile", "chunk", "settings",
        "quiet", "unban", "banned", "admins", "status", "log", "stop", "help",
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

    elif cmd == "chunk":
        try:
            n = max(1, int(arg))
        except ValueError:
            err("usage: chunk <N> — members per ban_members call")
            return
        _state["ban_chunk"] = n
        ok(f"ban chunk size → {n}")

    elif cmd == "settings":
        rows = [
            ("new title", _state["new_name"] or "(untouched)"),
            ("new bio", _state["new_bio"] or "(untouched)"),
            ("new avatar", _state["avatar"] or "(untouched)"),
            ("wipe avatars", _state["wipe_avatars"]),
            ("quiet (event messages off during pass)", _state["quiet_mode"]),
            ("slow_mode secs (group)", _state["slow_mode"] or "(untouched)"),
            ("reactions (group)", _state["reactions"] or "(untouched)"),
            ("restricted content (group/channel)", _tri_state(_state["restricted_content"])),
            ("sign messages (channel)", _tri_state(_state["sign_messages"])),
            ("channel privacy/username (channel)", _state["chat_username"] or "(untouched) — 'P' = private"),
            ("ban waves", "∞ — until the purge list is empty" if _state["ban_all"] else "off"),
            ("ban chunk / delay", f"{_state['ban_chunk']} members / {_state['ban_delay']}s"),
            ("protect admins / bots", f"{_state['protect_admins']} / {_state['protect_bots']}"),
            ("unban after the pass", _state["unban_after"]),
            ("profile vault", ", ".join(list(_load_profiles())[:6]) or "(empty)"),
            ("mode", "DRY RUN" if _state["dry_run"] else "LIVE"),
        ]
        _o(f"{_OX.EDGE}pending settings — exact values{_OX.RESET}")
        for k, v in rows:
            print(f"      {k:<40}: {v}")

    elif cmd == "quiet":
        if arg.lower() in ("on", "true", "1", "yes"):
            _state["quiet_mode"] = True
            warn("quiet mode ON — group event messages silenced during passes, restored after")
        elif arg.lower() in ("off", "false", "0", "no"):
            _state["quiet_mode"] = False
            ok("quiet mode OFF")
        else:
            _o(f"quiet mode is {_OX.LIVE + 'ON' if _state['quiet_mode'] else _OX.ASH + 'OFF'}{_OX.RESET} — usage: quiet on|off")

    elif cmd == "profile":
        _profiles_cmd(arg)

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
        print(f"  {_OX.VIOLET}║{_OX.RESET}  waves        : {s['rounds']} · scanned={s['scanned']} · chunk={_state['ban_chunk']}")
        print(f"  {_OX.VIOLET}║{_OX.RESET}  settings     : ok={s['settings_ok']} · refused={s['settings_failed']} · quiet={'ON' if _state['quiet_mode'] else 'off'}")
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
    {_OX.VIOLET}profile{_OX.RESET}         list saved identity profiles (the vault)
    {_OX.VIOLET}profile save <n>{_OX.RESET}  forge the current title/bio/avatar/chat settings as <n>
    {_OX.VIOLET}profile <n>{_OX.RESET}      instant-apply a saved profile
    {_OX.VIOLET}profile del <n>{_OX.RESET}   shatter a saved profile
    {_OX.VIOLET}chunk <N>{_OX.RESET}       members per ban_members call
    {_OX.VIOLET}settings{_OX.RESET}       every pending group/channel setting, exact values
    {_OX.VIOLET}real{_OX.RESET}           go LIVE (leaves dry-run; bans become irreversible)
    {_OX.VIOLET}unban{_OX.RESET}          lift every ban on the target
    {_OX.VIOLET}banned{_OX.RESET}         list banned members
    {_OX.VIOLET}admins{_OX.RESET}         list the untouchables (admins/creator)
    {_OX.VIOLET}quiet on|off{_OX.RESET}    silence group event messages during passes
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
        "avatar":         os.path.expanduser(str(opts.get("avatar") or "").strip().strip("'\"").strip()),
        "wipe_avatars":   bool(opts.get("wipe_avatars", True)),
        "ban_all":        bool(opts.get("ban_all", True)),
        "protect_admins": bool(opts.get("protect_admins", True)),
        "protect_bots":   bool(opts.get("protect_bots", True)),
        "ban_chunk":      max(1, num("ban_chunk", 10, int)),
        "ban_delay":      max(0.0, num("ban_delay", 2.0)),
        "slow_mode":      str(opts.get("slow_mode") or "").strip(),
        "reactions":      str(opts.get("reactions") or "").strip(),
        "restricted_content": str(opts.get("restricted_content") or "").strip(),
        "sign_messages":  str(opts.get("sign_messages") or "").strip(),
        "chat_username":  str(opts.get("chat_username") or "").strip().lstrip("@"),
        "quiet_mode":     bool(opts.get("quiet_mode", True)),
        "trigger_requires_self": bool(opts.get("trigger_requires_self", True)),
        "profile":        str(opts.get("profile") or "").strip(),
        "unban_after":    bool(opts.get("unban_after", True)),
        "dry_run":        bool(opts.get("dry_run", False)),
        "stats": {
            "kind": None, "guid": None, "members": 0, "admins": 0, "bots": 0,
            "banned": 0, "ban_failed": 0, "unbanned": 0,
            "scanned": 0, "rounds": 0, "quiet": None, "settings_ok": 0, "settings_failed": 0,
            "retitled": False, "rebioed": False,
            "avatars_old": 0, "avatars_new": 0, "started_at": None,
        },
        "log": [],
    })

    if _state["dry_run"]:
        warn("DRY RUN is ON — engage simulates everything and sends nothing")
    else:
        warn("LIVE MODE — engage sends real API calls (bans are irreversible; set dry_run True for a rehearsal)")

    try:
        app = Messenger(session)
    except Exception as e:
        err(f"client init failed: {e}")
        _state["running"] = False
        return

    _state["client"] = app

    def _read_self_guid():
        try:
            me = app.get_me()
        except Exception as e:
            _o(f"{_OX.ASH}ℹ get_me failed ({e}) — session identity unavailable{_OX.RESET}")
            return None
        u = _get(me, "user")
        return (_get(u, "guid") if u is not None else None) or _get(me, "guid") \
            or _get(me, "user_guid") or _get(me, "object_guid")

    _state["self_guid"] = _read_self_guid()

    # ── in-chat trigger — engage the chat the command was sent in ────────────
    @app.on_new_message()
    async def _handler(event):
        if not _state["running"]:
            return
        try:
            text = event.text
        except AttributeError:
            return
        hot, profile_name = _parse_trigger(text)
        if not hot:
            return

        chat = None
        for attr in ("chat_guid", "group_guid", "channel_guid", "object_guid"):
            chat = getattr(event, attr, None)
            if chat:
                break
        if not chat:
            _o(f"⚠ could not detect the chat id from the event")
            return
        if _kind_from_guid(chat) not in ("group", "channel"):
            _o(f"⚠ the trigger must be sent inside a group or channel (got {chat})")
            return
        if _state["engaging"]:
            warn("an engage pass is already running")
            return

        author = getattr(event, "author_guid", None)
        if _state["trigger_requires_self"]:
            mine = _state.get("self_guid")
            if mine:
                if author != mine:
                    return
            else:
                _o(f"{_OX.ASH}ℹ trigger fired without self-check — session identity unknown{_OX.RESET}")

        if profile_name:
            if profile_name not in _load_profiles():
                _o(f"{_OX.BLOOD}✗{_OX.RESET} trigger profile '{profile_name}' is not in the vault")
                return
            keep = (_state["ban_all"], _state["unban_after"], _state["dry_run"])
            _o(f"{_OX.EDGE}trigger '{_state['trigger']} {profile_name}' received — profile pass on {chat}{_OX.RESET}")
            threading.Thread(
                target=_profile_engage_thread,
                args=(app, chat, profile_name, keep),
                daemon=True,
                name="ssghost-profile",
            ).start()
            return

        self_guid = author or _state.get("self_guid")
        _o(f"{_OX.EDGE}trigger '{_state['trigger']}' received — engaging {chat}{_OX.RESET}")
        threading.Thread(
            target=_engage_worker,
            args=(app, chat, self_guid),
            daemon=True,
            name="ssghost-engage",
        ).start()

    # ───────────────────────────────────────────────── background listener ───────────────────────────────────────────────────
    _state["app_thread"] = threading.Thread(
        target=app.run,
        daemon=True,
        name="ssghost-listener",
    )
    _state["app_thread"].start()

    # ── Obsidian Vanguard boot splash ─────────────────────────────────────────
    if _state["profile"]:
        if _apply_profile(_state["profile"]):
            ok(f"profile '{_state['profile']}' armed — all saved fields drawn from the vault")
        else:
            err(f"profile '{_state['profile']}' is not in the vault — 'profile save {_state['profile']}' forges it")

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
    print(f"  {_OX.VIOLET}◼{_OX.RESET} purge waves   : ∞ (until the purge list is empty) · chunk={_state['ban_chunk']} · quiet={'ON' if _state['quiet_mode'] else 'off'}")
    vault = _load_profiles()
    print(f"  {_OX.VIOLET}◼{_OX.RESET} profile vault : {len(vault)} saved → {', '.join(list(vault)[:6]) or 'empty'}")
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
