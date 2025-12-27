import unittest
from utils import port_scan


class TestParsePorts(unittest.TestCase):
    def test_simple_list(self):
        self.assertEqual(port_scan.parse_ports('22,80'), [22, 80])

    def test_range(self):
        self.assertEqual(port_scan.parse_ports('100-102'), [100, 101, 102])

    def test_mixed(self):
        self.assertEqual(port_scan.parse_ports('22,80,100-101'), [22, 80, 100, 101])

    def test_invalid(self):
        self.assertEqual(port_scan.parse_ports('abc,70000,22'), [22])


if __name__ == '__main__':
    unittest.main()
