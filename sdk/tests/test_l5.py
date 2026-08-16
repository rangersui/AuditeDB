"""Integration tests for the embedded L5 Python SDK."""

from __future__ import annotations

import tempfile
import unittest

import l5


class EngineTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._root = tempfile.TemporaryDirectory(prefix="l5-python-test-")
        self.addCleanup(self._root.cleanup)
        self.db = l5.open(self._root.name, key=b"0" * 32)
        self.addCleanup(self.db.close)

    def test_representation_roundtrip_and_mapping_protocol(self) -> None:
        self.db.put(
            "home/note",
            b"hello",
            content_type="text/plain; charset=utf-8",
            headers={"x-meta-owner": "ranger"},
        )
        self.db["home/json"] = b'{"answer": 42}'

        self.assertEqual(self.db.get("home/note"), b"hello")
        self.assertEqual(self.db.get_text("home/note"), "hello")
        self.assertEqual(self.db.get_json("home/json"), {"answer": 42})
        self.assertEqual(self.db["home/json"], b'{"answer": 42}')
        self.assertIn("home/note", self.db)
        self.assertNotIn("home/missing", self.db)
        self.assertEqual(set(self.db), {"home/json", "home/note"})
        self.assertEqual(len(self.db), 2)

        metadata = self.db.head("home/note")
        self.assertEqual(metadata["content-type"], "text/plain; charset=utf-8")
        self.assertEqual(metadata["content-length"], "5")
        self.assertEqual(metadata["x-meta-owner"], "ranger")
        self.assertTrue(metadata["etag"].startswith("hmac-"))

    def test_empty_append_delete_and_missing_semantics(self) -> None:
        self.db.put("home/empty", b"")
        self.assertEqual(self.db.get("home/empty"), b"")

        self.db.append("home/log", b"line1\n")
        self.db.append("home/log", b"line2\n")
        self.assertEqual(self.db.get("home/log"), b"line1\nline2\n")

        self.assertTrue(self.db.delete("home/log"))
        self.assertFalse(self.db.delete("home/log"))
        with self.assertRaises(l5.NotFound):
            self.db.get("home/log")
        with self.assertRaises(KeyError):
            _ = self.db["home/log"]

    def test_preconditions_and_validation_are_typed(self) -> None:
        self.db.put("home/cas", b"one")
        etag = self.db.head("home/cas")["etag"]
        self.db.put("home/cas", b"two", if_match=etag)

        with self.assertRaises(l5.PreconditionFailed):
            self.db.put("home/cas", b"stale", if_match=etag)
        with self.assertRaises(l5.PreconditionFailed):
            self.db.put("home/cas", b"exists", if_none_match="*")
        with self.assertRaises(l5.InvalidWorld):
            self.db.put("../../escape", b"no")
        with self.assertRaises(l5.InvalidMetadata):
            self.db.put(
                "home/injected",
                b"no",
                content_type="text/plain\r\nx-injected: yes",
            )

    def test_audit_and_introspection_report_engine_state(self) -> None:
        self.db.put("home/audit", b"first")
        self.db.append("home/audit", b"-second")

        self.assertTrue(self.db.verify("home/audit"))
        head = self.db.chain_head("home/audit")
        self.assertIsNotNone(head)
        assert head is not None
        self.assertEqual(head["events"], 3)
        self.assertRegex(str(head["genesis"]), r"^hmac-[0-9a-f]{64}$")
        self.assertRegex(str(head["latest"]), r"^hmac-[0-9a-f]{64}$")
        self.assertEqual(self.db.list_worlds(), ["home/audit"])
        self.assertEqual(self.db.ls(), ["home/audit"])
        usage_by_world = self.db.du()
        self.assertEqual(set(usage_by_world), {"home/audit"})
        self.assertGreater(usage_by_world["home/audit"], 0)

        usage = self.db.df()
        self.assertEqual(usage["worlds"], 1)
        self.assertEqual(usage["storage_audit_chain_events"], 3)
        self.assertGreaterEqual(usage["storage_used"], len(b"first-second"))

    def test_context_manager_closes_engine(self) -> None:
        with tempfile.TemporaryDirectory(prefix="l5-python-context-") as root:
            with l5.open(root, key=b"1" * 32) as db:
                db.put("home/context", b"ok")
                self.assertEqual(db.get("home/context"), b"ok")
                live_subscription = db.subscribe("home/context")
                native_subscription = live_subscription._subscription

            with self.assertRaises(RuntimeError):
                db.get("home/context")
            self.assertEqual(native_subscription.next(100).kind.name, "CLOSED")
            self.assertEqual(live_subscription.next(), {"kind": "closed"})

            with l5.open(root, key=b"1" * 32) as reopened:
                self.assertEqual(reopened.get("home/context"), b"ok")
                self.assertTrue(reopened.verify("home/context"))

    def test_subscription_delivers_write_and_closes_cleanly(self) -> None:
        subscription = self.db.subscribe("home/events/*")
        native_subscription = subscription._subscription
        try:
            self.db.put("home/events/one", b"payload")
            self.db.put("home/events/one", b"payload-2")
            events = []
            for _ in range(3):
                event = subscription.next(timeout_ms=1000)
                self.assertIsNotNone(event)
                assert event is not None
                self.assertEqual(event["kind"], "event")
                self.assertEqual(event["path"], "home/events/one")
                events.append(event)

            self.assertEqual(
                [event["verb"] for event in events],
                ["format", "replace", "replace"],
            )
            event_ids = [int(event["id"]) for event in events]
            self.assertEqual(event_ids, sorted(set(event_ids)))
            self.assertEqual(len({event["cursor"] for event in events}), 3)
            self.assertTrue(all(str(event["etag"]).startswith("hmac-") for event in events))
        finally:
            subscription.close()

        self.assertEqual(native_subscription.next(100).kind.name, "CLOSED")
        self.assertEqual(subscription.next(), {"kind": "closed"})

        with self.assertRaisesRegex(RuntimeError, "subscription body failed"):
            with self.db.subscribe("home/exceptional/*") as exceptional:
                exceptional_native = exceptional._subscription
                raise RuntimeError("subscription body failed")
        self.assertEqual(exceptional_native.next(100).kind.name, "CLOSED")
        self.assertEqual(exceptional.next(), {"kind": "closed"})


if __name__ == "__main__":
    unittest.main()
