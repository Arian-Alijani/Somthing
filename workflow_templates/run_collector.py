"""Resolve GitHub Actions inputs and persist the independent scheduled profile."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PROFILE = ROOT / "workflow_templates" / "auto_config.json"
DEFAULT_HOURS = "00,05,10,15,20"
MINUTE = 17
DEFAULTS = dict(per_channel=20, max_pages=15, workers=10, request_timeout=30, retries=3,
                geoip="on", channel_source="listed", channels="", utc_hours=DEFAULT_HOURS)
BOUNDS = dict(per_channel=10000, max_pages=1000, workers=32, request_timeout=120, retries=8)


def normalize_profile(values):
    if not isinstance(values, dict) or values.keys() - DEFAULTS.keys():
        raise ValueError("Unexpected automatic profile fields.")
    profile = DEFAULTS | values
    for name, upper in BOUNDS.items():
        value = str(profile[name]).strip()
        if name == "per_channel" and value.lower() == "all":
            profile[name] = "all"
            continue
        if not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= upper:
            raise ValueError(f"{name}: expected a number from 1 to {upper}"
                             + (" or 'all'" if name == "per_channel" else ""))
        profile[name] = int(value)
    if profile["geoip"] not in ("on", "off"):
        raise ValueError("geoip: expected on or off")
    raw_hours = str(profile["utc_hours"]).strip().lower()
    if raw_hours == "off":
        profile["utc_hours"] = "off"
    else:
        hours = re.split(r"[\s,،;]+", raw_hours)
        if any(not re.fullmatch(r"[0-9]{1,2}", h) or int(h) > 23 for h in hours):
            raise ValueError("utc_hours: use comma-separated UTC hours (00–23) or 'off'")
        profile["utc_hours"] = ",".join(f"{h:02d}" for h in sorted({int(h) for h in hours}))
    if not isinstance(profile["channels"], str) or profile["channel_source"] not in ("listed", "custom"):
        raise ValueError("Use a textual channels field and a listed or custom source.")
    profile["channels"] = profile["channels"].strip()
    return profile


def scheduled_hour(cron):
    match = re.fullmatch(rf"{MINUTE} ([0-9]{{1,2}}) \* \* \*", cron)
    if not match or int(match[1]) > 23:
        raise ValueError(f"Unexpected scheduled trigger: {cron!r}")
    return f"{int(match[1]):02d}"


def selected_slot(cron, utc_hours):
    # Use the triggering cron, not runner wall-clock time (which may be delayed).
    return scheduled_hour(cron) in utc_hours.split(",")


def should_run(kind):
    if kind == "workflow_dispatch":
        return True
    if kind == "schedule":
        # Recheck the latest profile after checkout, including on re-run.
        return selected_slot(os.environ.get("EVENT_CRON", ""), read_profile()["utc_hours"])
    raise ValueError(f"Unsupported event: {kind!r}")


def read_profile():
    if not PROFILE.exists():
        return normalize_profile({})
    return normalize_profile(json.loads(PROFILE.read_text(encoding="utf-8")))


def manual_profile(include_schedule=False):
    names = DEFAULTS if include_schedule else DEFAULTS.keys() - {"utc_hours"}
    values = {}
    for name in names:
        raw = os.environ.get("FORM_" + name.upper(), "").strip()
        if raw:
            values[name] = raw
    return normalize_profile(values)


def run_collector(profile):
    env = os.environ | {
        "WORKERS": str(profile["workers"]), "REQUEST_TIMEOUT": str(profile["request_timeout"]),
        "RETRIES": str(profile["retries"]), "GEOIP_ENABLED": "1" if profile["geoip"] == "on" else "0",
        "PYTHONUNBUFFERED": "1",
    }
    command = [sys.executable, "-B", str(ROOT / "collector.py"),
               "--max-pages", str(profile["max_pages"]),
               "--channel-source", profile["channel_source"], "--channels=" + profile["channels"]]
    if profile["per_channel"] == "all":
        command.append("--all-configs")
    else:
        command.extend(["--per-channel", str(profile["per_channel"])])
    return subprocess.run(command, cwd=ROOT, env=env, check=False).returncode


def main():
    event = os.environ.get("GITHUB_EVENT_NAME")
    try:
        if not should_run(event):
            print("This UTC hour is not enabled for automatic collection.")
            return 0
        action = os.environ.get("FORM_ACTION") if event == "workflow_dispatch" else "run_now"
        action = action or "run_now"
        if action == "save_auto":
            if os.environ.get("GITHUB_REF") != "refs/heads/" + os.environ["DEFAULT_BRANCH"]:
                raise ValueError("Select the default branch to save automatic settings.")
            from collector import select_channels

            profile = manual_profile(include_schedule=True)
            if not select_channels(profile["channel_source"], profile["channels"]):
                raise ValueError("No public channels selected.")
            PROFILE.write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"Automatic UTC hours saved: {profile['utc_hours']} (minute :{MINUTE:02d}). No collection started.")
            return 0
        if action != "run_now":
            raise ValueError(f"Unknown action: {action!r}")
        return run_collector(read_profile() if event == "schedule" else manual_profile())
    except (OSError, ValueError, KeyError) as exc:
        print(f"Collector settings error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
