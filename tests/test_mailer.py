import unittest
from email import policy
from email.parser import BytesParser

from wp_guardian.config import GuardianConfig
from wp_guardian.mailer import build_message, validate_recipient


class MailerTests(unittest.TestCase):
    def test_build_message_contains_report_and_recipient(self) -> None:
        config = GuardianConfig(
            mail_enabled=True,
            mail_recipients=("skr@softico.ua",),
            mail_subject_prefix="[WP Guardian]",
        )
        payload = build_message(
            config,
            "SOFTICO WORDPRESS GUARDIAN\nFindings: 0\n",
            hostname="web.softico.ua",
        )
        message = BytesParser(policy=policy.default).parsebytes(payload)

        self.assertEqual(message["To"], "skr@softico.ua")
        self.assertEqual(message["From"], "wp-guardian@web.softico.ua")
        self.assertEqual(
            message["Subject"],
            "[WP Guardian] web.softico.ua audit report",
        )
        self.assertIn("Findings: 0", message.get_content())

    def test_rejects_header_injection(self) -> None:
        with self.assertRaises(ValueError):
            validate_recipient("skr@softico.ua\nBcc: attacker@example.com")


if __name__ == "__main__":
    unittest.main()
