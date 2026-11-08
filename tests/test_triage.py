from hashlib import sha256
from pathlib import Path
import unittest
from triage import analyze, LIMIT


class MailTests(unittest.TestCase):
    def test_invoice(self):
        raw = (Path(__file__).resolve().parents[1] / "examples/invoice.eml").read_bytes()
        report = analyze(raw)
        self.assertTrue(report["reply_mismatch"])
        self.assertEqual(report["link_mismatches"], [
            {"displayed_host":"billing.example", "destination_host":"portal.example"}])
        self.assertEqual(report["attachments"][0]["sha256"], sha256(b"invoice\n").hexdigest())

    def test_clean_message_and_unrelated_links(self):
        raw = b'From: a@lab.example\nContent-Type: text/html\n\n<a href="https://LAB.example/x">https://lab.example/y</a>'
        report = analyze(raw)
        self.assertFalse(report["reply_mismatch"])
        self.assertEqual(report["link_mismatches"], [])

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            analyze(b"x" * (LIMIT + 1))
