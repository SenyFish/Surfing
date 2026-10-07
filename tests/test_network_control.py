"""Run the real ctr.inotify against temporary paths and mocked Android commands.

No commands address the host firewall or a connected phone.
Run: python -m unittest discover -s tests -v
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"
CHAINS = [("mangle", "BOX_LOCAL"), ("mangle", "BOX_EXTERNAL"),
          ("nat", "CLASH_DNS_LOCAL"), ("nat", "CLASH_DNS_EXTERNAL")]


def shell_path(path):
    text = Path(path).as_posix()
    if os.name == "nt":
        return f"/{text[0].lower()}{text[2:]}"
    return text


class NetworkControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("scripts", "bin", "run", "tmp", "module"):
            (self.root / name).mkdir()
        self.state_file = self.root / "firewall.json"
        self.write_state({"chains": {
            f"ipv4:{table}:{chain}": ["-j PROXY"] for table, chain in CHAINS
        }})
        self.wifi(True)
        self.configure()
        self.command("magisk", "exit 1")
        self.command("cmd", 'cat "$TEST_WIFI"')
        self.command("dumpsys", 'cat "$TEST_DUMPSYS"')
        self.command("ip", "echo '    inet 192.0.2.10/24 scope global wlan0'")
        self.command("iptables", 'python "$TEST_MOCK" "$TEST_STATE" ipv4 "$@"')
        self.command("ip6tables", 'python "$TEST_MOCK" "$TEST_STATE" ipv6 "$@"')
        # Git Bash lacks flock. Linux CI uses the real kernel lock and runs
        # the concurrency test; Windows still exercises the state machine.
        if os.name == "nt":
            self.command("flock", "exit 0")
        source_path = Path(os.environ.get("SURFING_TEST_SOURCE", ROOT / "box_bll/scripts/ctr.inotify"))
        source = source_path.read_text(encoding="utf-8")
        replacements = {
            "/data/adb/box_bll/bin": shell_path(self.root / "bin"),
            "/system/bin/iptables": shell_path(self.root / "bin/iptables"),
            "/system/bin/ip6tables": shell_path(self.root / "bin/ip6tables"),
            "/system/bin/ip": shell_path(self.root / "bin/ip"),
            "/data/adb/modules/Surfing": shell_path(self.root / "module"),
            "/data/adb/box_bll": shell_path(self.root),
            "/dev/tmp/": shell_path(self.root / "tmp") + "/",
        }
        for old, new in replacements.items():
            source = source.replace(old, new)
        self.script = self.root / "scripts/ctr.inotify"
        self.script.write_text(source, encoding="utf-8", newline="\n")
        self.env = os.environ.copy()
        self.env.update({
            "TEST_WIFI": shell_path(self.root / "wifi.txt"),
            "TEST_DUMPSYS": shell_path(self.root / "dumpsys.txt"),
            "TEST_MOCK": shell_path(ROOT / "tests/fake_iptables.py"),
            "TEST_STATE": shell_path(self.state_file),
        })

    def command(self, name, body):
        path = self.root / "bin" / name
        path.write_text("#!/bin/sh\n" + body + "\n", newline="\n")
        path.chmod(0o755)

    def configure(self, **overrides):
        config = {
            "enable_network_service_control": "true", "bypass_via_iptables": "true",
            "enable_cellular_proxy": "true", "enable_wifi_proxy": "true",
            "enable_ssid_filter": "true", "enable_mac_filter": "false",
            "use_wifi_list_mode": "blacklist", "blacklist_wifi_ssids": "HOME,OTHER",
            "whitelist_wifi_ssids": "HOME", "netfilt_logs": "true",
            "run_path": shell_path(self.root / "run"),
        }
        config.update(overrides)
        (self.root / "scripts/box.config").write_text(
            "".join(f'{key}="{value}"\n' for key, value in config.items()), newline="\n")

    def wifi(self, connected, ssid="HOME"):
        (self.root / "wifi.txt").write_text(
            f'Wifi is connected to "{ssid}"\n' if connected else "Wifi is disabled\n")
        (self.root / "dumpsys.txt").write_text(
            f'mWifiInfo SSID: "{ssid}", BSSID: aa:bb:cc:dd:ee:ff, IP: /192.0.2.10\n'
            if connected else "mWifiInfo SSID: <unknown ssid>, BSSID: <none>\n")

    def read_state(self):
        return json.loads(self.state_file.read_text())

    def write_state(self, state):
        self.state_file.write_text(json.dumps(state))

    def invoke(self, force=True, event="w", wait=True):
        args = [BASH, shell_path(self.script), event]
        if force:
            args.append("force")
        if not wait:
            return subprocess.Popen(args, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = subprocess.run(args, env=self.env, capture_output=True, text=True, timeout=30)
        return result

    @property
    def marker(self):
        return self.root / "tmp/wifi_bypassed"

    def assert_bypassed(self, family="ipv4"):
        chains = self.read_state()["chains"]
        for table, chain in CHAINS:
            rules = chains[f"{family}:{table}:{chain}"]
            self.assertEqual(rules[0], "-j NET_BYPASS")
            self.assertEqual(rules.count("-j NET_BYPASS"), 1)
        self.assertTrue(self.marker.exists())

    def test_stale_marker_after_firewall_rebuild(self):
        self.marker.touch()
        self.assertEqual(self.invoke().returncode, 0)
        self.assert_bypassed()

    def test_bypass_must_precede_proxy_and_accept_first(self):
        self.invoke()
        state = self.read_state()
        state["chains"]["ipv4:mangle:BOX_LOCAL"] = ["-j PROXY", "-j NET_BYPASS"]
        state["chains"]["ipv4:nat:NET_BYPASS"] = ["-j DROP", "-j ACCEPT"]
        self.write_state(state)
        self.invoke()
        self.assert_bypassed()
        self.assertEqual(self.read_state()["chains"]["ipv4:nat:NET_BYPASS"], ["-j ACCEPT"])

    def test_manual_disable_preserved_on_wifi_and_cellular(self):
        self.marker.touch()
        disabled = self.root / "module/disable"
        disabled.touch()
        before = self.read_state()
        for connected in (False, True):
            self.wifi(connected)
            self.assertEqual(self.invoke().returncode, 0)
            self.assertTrue(disabled.exists())
            self.assertEqual(self.read_state(), before)

    def test_wifi_cellular_wifi_transitions(self):
        self.invoke()
        self.assert_bypassed()
        self.wifi(False)
        self.assertEqual(self.invoke().returncode, 0)
        self.assertFalse(self.marker.exists())
        for rules in self.read_state()["chains"].values():
            self.assertNotIn("-j NET_BYPASS", rules)
        self.wifi(True)
        self.invoke()
        self.assert_bypassed()

    def test_cellular_cleans_orphaned_rules_without_marker(self):
        self.invoke()
        self.marker.unlink()
        self.wifi(False)
        self.invoke()
        for rules in self.read_state()["chains"].values():
            self.assertNotIn("-j NET_BYPASS", rules)

    def test_ipv6_rules_are_verified(self):
        state = self.read_state()
        state["chains"].update({f"ipv6:{table}:{chain}": ["-j PROXY"] for table, chain in CHAINS})
        self.write_state(state)
        self.invoke()
        self.assert_bypassed("ipv4")
        self.assert_bypassed("ipv6")

    def test_failed_injection_does_not_commit_marker(self):
        self.marker.touch()
        state = self.read_state()
        state["failure"] = {"action": "-I", "chain": "BOX_LOCAL"}
        self.write_state(state)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_no_proxy_chains_does_not_commit_marker(self):
        self.write_state({"chains": {}})
        self.marker.touch()
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_failed_cleanup_keeps_bypassed_state(self):
        self.invoke()
        state = self.read_state()
        state["failure"] = {"action": "-D", "chain": "BOX_LOCAL"}
        self.write_state(state)
        self.wifi(False)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertTrue(self.marker.exists())

    def test_whitelist_and_service_control_modes(self):
        self.configure(use_wifi_list_mode="whitelist")
        self.invoke()
        self.assertFalse(self.marker.exists())
        self.wifi(True, "PUBLIC")
        self.invoke()
        self.assert_bypassed()
        self.configure(bypass_via_iptables="false", use_wifi_list_mode="whitelist")
        self.invoke()
        self.assertTrue((self.root / "module/disable").exists())
        self.wifi(False)
        self.invoke()
        self.assertFalse((self.root / "module/disable").exists())

    def test_close_network_event_is_processed(self):
        self.invoke()
        self.wifi(False)
        (self.root / "tmp/last_check_time").write_text(str(int(time.time()) + 1))
        self.invoke(force=False)
        self.assertFalse(self.marker.exists())

    def test_ignored_event_does_not_mutate_firewall(self):
        before = self.read_state()
        self.assertEqual(self.invoke(event="a").returncode, 0)
        self.assertEqual(self.read_state(), before)

    @unittest.skipIf(os.name == "nt", "kernel flock tested in Linux CI and on Android")
    def test_manual_disable_while_waiting_for_lock(self):
        import fcntl

        with (self.root / "tmp/netfilter.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            process = self.invoke(wait=False)
            time.sleep(0.2)
            self.assertIsNone(process.poll())
            (self.root / "module/disable").touch()
            before = self.read_state()
            fcntl.flock(lock, fcntl.LOCK_UN)
            output, errors = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, (output, errors))
            self.assertEqual(self.read_state(), before)

    @unittest.skipIf(os.name == "nt", "kernel flock tested in Linux CI and on Android")
    def test_concurrent_handlers_are_idempotent(self):
        processes = [self.invoke(wait=False) for _ in range(3)]
        for process in processes:
            output, errors = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, (output, errors))
        self.assert_bypassed()


if __name__ == "__main__":
    unittest.main()
