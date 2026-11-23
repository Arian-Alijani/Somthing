import base64
import contextlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import collector
from workflow_templates import run_collector as runner


A = "vless://id@one.example:443?security=reality&type=ws"
B = "trojan://secret@[2001:db8::1]:443"
C = "vless://id@three.example:443"


def encode(text):
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def post(number, text, channel="TestChannel", kind="text"):
    return (f'<div data-post="{channel}/{number}" class="tgme_widget_message js-widget_message">'
            f'<div class="js-message_text tgme_widget_message_{kind}">{text}</div></div>')


class ChannelTests(unittest.TestCase):
    def test_listed_defaults_and_exact_subset(self):
        with patch.object(collector, "load_channels", return_value=["Alpha", "Bravo", "Charlie"]):
            self.assertEqual(collector.select_channels("listed"), ["Alpha", "Bravo", "Charlie"])
            self.assertEqual(collector.select_channels("listed", "@bravo، https://t.me/s/ALPHA/10 bravo"),
                             ["Alpha", "Bravo"])
            with self.assertRaises(ValueError):
                collector.select_channels("listed", "@Other")

    def test_custom_uses_only_requested_channels(self):
        with patch.object(collector, "load_channels", side_effect=AssertionError):
            self.assertEqual(collector.select_channels("custom", "New_Channel; t.me/other_1 @new_channel"),
                             ["New_Channel", "other_1"])
            for invalid in ("", "-10012345", "https://t.me/+Invite", "https://t.me/c/12/34",
                            "https://t.me.evil.example/Alpha", "a/../other", "@Not-A-Username"):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    collector.select_channels("custom", invalid)


class ExtractionTests(unittest.TestCase):
    def test_formats_and_post_boundaries(self):
        html = (f'<div class="tgme_page_description">{C}</div>'
                + post(7, "«" + A.replace("&", "&amp;").replace("one", "<b>one</b>") + "»")
                + post(8, f'<blockquote expandable><pre><code>{B}</code><br/>{encode(C)}</pre></blockquote>'
                          f'<a href="{A.replace("&", "&amp;")}">Copy</a>', kind="caption")
                + post(100, "vless://id@ignored.example:443", channel="Different"))
        with patch.object(collector, "fetch", return_value=html):
            self.assertEqual(collector.collect_from_channel("testchannel", 10, 1), [B, C, A])

    def test_mixed_formats_keep_text_order(self):
        text = f'{A}\n{encode(B)}\n({C}),{A}'
        self.assertEqual(collector.extract_configs_from_text(text), [A, B, C])

    def test_bad_authorities_and_payloads_are_rejected(self):
        invalid = ["http://site.example/path:443", "vless://id@one.example:65536",
                   "vless://one.example:443", "vmess://" + encode('{"wrong":"field"}'),
                   "ss://" + encode("arbitrary words, not a config"), "trojan://pass@[bad]:443"]
        self.assertEqual(collector.extract_configs_from_text("\n".join(invalid)), [])

    def test_vmess_ss_and_ssr_legacy_forms(self):
        vmess = "vmess://" + encode(json.dumps({"add": "example.test", "port": 443, "id": "abc", "ps": "old"}))
        legacy = "vmess://id@example.test:443?type=ws"
        ss = "ss://" + encode("aes-256-gcm:mySecret@example.test:443")
        ssr = "ssr://" + encode("example.test:443:origin:aes-256-cfb:plain:cGFzcw")
        for config in (vmess, legacy, ss, ssr):
            with self.subTest(config=config):
                self.assertTrue(collector.is_valid_config(config))
                self.assertEqual(collector.extract_host_port(config), ("example.test", "443"))
                self.assertEqual(collector.config_hash(config), collector.config_hash(collector.set_remark(config, "new")))
        self.assertNotEqual(collector.config_hash("ss://Secret@example.test:443"),
                            collector.config_hash("ss://secret@example.test:443"))

    def test_pagination_uses_own_posts_and_stops_on_repeated_page(self):
        latest = post(9, B) + post(10, encode(A)) + post(1, C, channel="Other")
        older = post(9, B + "#repeat") + post(7, C)
        with patch.object(collector, "fetch", side_effect=[latest, older, older]) as fetch:
            self.assertEqual(collector.collect_from_channel("TestChannel", None, 10), [A, B, C])
        self.assertEqual([call.args[0] for call in fetch.call_args_list],
                         ["https://t.me/s/TestChannel", "https://t.me/s/TestChannel?before=9",
                          "https://t.me/s/TestChannel?before=7"])
        with patch.object(collector, "fetch", return_value=latest) as fetch:
            self.assertEqual(collector.collect_from_channel("TestChannel", 1, 15), [A])
            fetch.assert_called_once()

    def test_snapshot_does_not_keep_configs_from_previous_channel_selection(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT / "tests") as directory:
            root = Path(directory)
            sub = root / "sub"
            sub.mkdir()
            for name in ("trojan.txt", "trojan_b64.txt"):
                (sub / name).write_text(B)
            settings = dict(SUB_DIR=str(sub), DATA_DIR=str(root / "data"),
                            SUB_PLAIN=str(sub / "configs.txt"), SUB_B64=str(sub / "sub.txt"),
                            RAW_FILE=str(root / "data" / "all_configs.txt"))
            with patch.multiple(collector, **settings):
                collector.write_outputs({"all": [A], "vless": [A], "trojan": []})
            self.assertEqual((sub / "all.txt").read_text().splitlines(), [A])
            self.assertEqual((sub / "trojan.txt").read_text(), "")
            self.assertEqual((sub / "trojan_b64.txt").read_text(), "")

    def test_empty_run_never_writes_subscriptions(self):
        with patch.object(collector, "collect_all", return_value=[]), patch.object(collector, "write_outputs") as write:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(collector.main(["--channel-source", "custom", "--channels", "Alpha"]), 1)
            write.assert_not_called()


class ScheduleTests(unittest.TestCase):
    def test_template_covers_every_slot_once(self):
        template = (runner.ROOT / "workflow_templates/collect.yml").read_text()
        slots = [runner.scheduled_hour(cron) for cron in re.findall(r'- cron: "([^"]+)"', template)]
        self.assertEqual(slots, [f"{hour:02d}" for hour in range(24)])

    def test_validation_and_trigger_identity(self):
        self.assertEqual(runner.normalize_profile({"utc_hours": "20، 4,04"})["utc_hours"], "04,20")
        self.assertTrue(runner.selected_slot("17 4 * * *", "04,20"))
        self.assertFalse(runner.selected_slot("17 4 * * *", "off"))
        self.assertFalse(runner.selected_slot("17 20 * * *", "04"))
        for values in ({"utc_hours": "24"}, {"utc_hours": "2:17"}, {"workers": "0"}, {"retries": "2;echo"}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                runner.normalize_profile(values)

    def test_saved_profile_applies_only_to_scheduled_runs(self):
        with tempfile.TemporaryDirectory(dir=runner.ROOT / "tests") as directory:
            profile_file = Path(directory) / "auto_config.json"
            with patch.object(runner, "PROFILE", profile_file), patch.object(runner, "run_collector", return_value=0) as run:
                with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "FORM_ACTION": "save_auto",
                                             "FORM_UTC_HOURS": "3,15", "FORM_PER_CHANNEL": "all", "FORM_MAX_PAGES": "6",
                                             "FORM_CHANNEL_SOURCE": "custom", "FORM_CHANNELS": "@Alpha",
                                             "GITHUB_REF": "refs/heads/master", "DEFAULT_BRANCH": "master"}, clear=True):
                    self.assertEqual(runner.main(), 0)
                    run.assert_not_called()
                saved = profile_file.read_text()
                with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule", "EVENT_CRON": "17 15 * * *"}, clear=True):
                    self.assertEqual(runner.main(), 0)
                    self.assertEqual(run.call_args.args[0]["per_channel"], "all")
                    self.assertEqual(run.call_args.args[0]["channels"], "@Alpha")
                run.reset_mock()
                with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule", "EVENT_CRON": "17 13 * * *"}, clear=True):
                    self.assertEqual(runner.main(), 0)
                    run.assert_not_called()
                with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "FORM_PER_CHANNEL": "5"}, clear=True):
                    self.assertEqual(runner.main(), 0)
                    self.assertEqual(run.call_args.args[0]["per_channel"], 5)
                    self.assertEqual(run.call_args.args[0]["channel_source"], "listed")
                    self.assertEqual(profile_file.read_text(), saved)

    def test_command_receives_literal_channel_argument_and_network_settings(self):
        profile = runner.normalize_profile({"per_channel": "all", "channels": "@Alpha,@Bravo",
                                            "geoip": "off", "request_timeout": 12, "retries": 2})
        with patch.object(runner.subprocess, "run") as run:
            runner.run_collector(profile)
        args = run.call_args.args[0]
        self.assertIn("--channels=@Alpha,@Bravo", args)
        self.assertIn("--all-configs", args)
        env = run.call_args.kwargs["env"]
        self.assertEqual((env["REQUEST_TIMEOUT"], env["RETRIES"], env["GEOIP_ENABLED"]), ("12", "2", "0"))


if __name__ == "__main__":
    unittest.main()
