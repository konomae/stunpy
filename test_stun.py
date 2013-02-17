# coding: utf-8
import stun
import unittest


class TestStunFunctions(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_generate_transaction_id_length(self):
        transaction_id = stun.generate_transaction_id()
        self.assertEquals(12, len(transaction_id))

    def test_generate_transaction_id_unique(self):
        transaction_id1 = stun.generate_transaction_id()
        transaction_id2 = stun.generate_transaction_id()
        self.assertNotEqual(transaction_id1, transaction_id2)

    def test_ip_to_bytes(self):
        addr_bytes = stun.ip_to_bytes('192.168.11.1', False)
        self.assertEqual('\xc0\xa8\x0b\x01', addr_bytes)

    def test_ip_to_bytes_xor(self):
        addr_bytes = stun.ip_to_bytes('192.168.11.1', True)
        self.assertEqual('\xe1\xba\xafC', addr_bytes)

    def test_port_to_bytes(self):
        port_bytes = stun.port_to_bytes(1234, False)
        self.assertEqual('\x04\xd2', port_bytes)

    def test_port_to_bytes_xor(self):
        port_bytes = stun.port_to_bytes(1234, True)
        self.assertEqual('%\xc0', port_bytes)

    def test_read_mapped_address(self):
        attr_type = '\x00\x01'
        attr_body = '\x00\x01\x04\xd2\xc0\xa8\x0b\x01'
        attr_len = 8
        mapped_address = stun.read_mapped_address(attr_type, attr_body, attr_len)
        self.assertEqual(
            dict(ip='192.168.11.1', port=1234, family='IPv4', name='MAPPED-ADDRESS'),
            mapped_address
        )

    def test_read_mapped_address_xor(self):
        attr_type = '\x00\x20'
        attr_body = '\x00\x01%\xc0\xe1\xba\xafC'
        attr_len = 8
        mapped_address = stun.read_mapped_address(attr_type, attr_body, attr_len)
        self.assertEqual(
            dict(ip='192.168.11.1', port=1234, family='IPv4', name='XOR-MAPPED-ADDRESS'),
            mapped_address
        )

