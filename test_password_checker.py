import hashlib
import unittest
from unittest.mock import patch

import password_checker as pc


class TestPasswordChecker(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(pc.evaluate("password").score, 0)

    def test_leetspeak_common_password_is_caught(self):
        self.assertEqual(pc.evaluate("p@ssw0rd").score, 0)

    def test_long_random_password_is_very_strong(self):
        self.assertEqual(pc.evaluate("T7#qv!Lm2@Rz9&Wx").score, 4)

    def test_sequences_are_detected(self):
        self.assertTrue(pc.has_sequence("myabcdpass"))
        self.assertTrue(pc.has_sequence("x9876y"))
        self.assertTrue(pc.has_sequence("Qwerty!"))
        self.assertFalse(pc.has_sequence("T7#qv!Lm"))

    def test_repeats_are_detected(self):
        self.assertTrue(pc.has_repeats("heyyyy"))
        self.assertTrue(pc.has_repeats("abcabc"))
        self.assertFalse(pc.has_repeats("abcdef"))

    def test_short_password_gets_length_tip(self):
        self.assertIn("Use at least 12 characters.", pc.evaluate("Ab1!").feedback)

    def test_word_plus_year_is_penalised(self):
        self.assertLessEqual(pc.evaluate("Summer2024!").score, 1)

    def test_empty_password(self):
        result = pc.evaluate("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.entropy_bits, 0)

    def test_breached_password_forced_to_zero(self):
        with patch.object(pc, "check_breach", return_value=5000):
            result = pc.evaluate("T7#qv!Lm2@Rz9&Wx", breach_check=True)
        self.assertEqual(result.score, 0)
        self.assertIn("5,000", result.feedback[0])

    def test_breach_lookup_sends_only_hash_prefix(self):
        password = "hello"
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        body = f"{sha1[5:]}:42\nABCDEF:1".encode()

        class FakeResponse:
            def read(self):
                return body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        with patch("urllib.request.urlopen", return_value=FakeResponse()) as mock_open:
            self.assertEqual(pc.check_breach(password), 42)
        url = mock_open.call_args[0][0].full_url
        self.assertTrue(url.endswith(sha1[:5]))
        self.assertNotIn(password, url)


if __name__ == "__main__":
    unittest.main()
