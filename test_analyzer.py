import unittest
from analyzer import parse_line, is_error

class TestParser(unittest.TestCase):

    def test_valid_line(self):
        result = parse_line('27.174.72.39 - - [01/Jun/2026:00:00:00 +0000] "GET /static/style.css HTTP/1.1" 200 6741 "-" "Mozilla/5.0 (X11; Linux x86_64)"')
        self.assertIsNotNone(result)
        self.assertEqual(result["ip"], "27.174.72.39")
        self.assertEqual(result["status"], "200")
        self.assertEqual(result["method"], "GET")


    def test_bad_line(self):
        result = parse_line('garbage-144 <<< malformed line')
        self.assertIsNone(result)

    def test_error_status(self):
        result = parse_line('64.220.229.111 - - [01/Jun/2026:00:00:00 +0000] "GET /login HTTP/1.1" 404 58 "-" "curl/8.4.0"')
        status = result["status"]
        self.assertTrue(is_error(status))

    def test_is_error(self):
        self.assertTrue(is_error("404"))
        self.assertTrue(is_error("500"))
        self.assertFalse(is_error("200"))

if __name__ == "__main__":
    unittest.main()