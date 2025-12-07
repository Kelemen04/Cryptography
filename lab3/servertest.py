import unittest
from unittest.mock import MagicMock
import keyserver


class TestKeyServer(unittest.TestCase):

    def setUp(self):
        keyserver.public_keys = {}

    def test_handle_client_register_success(self):
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"REGISTER|8001|FAKE_PUBLIC_KEY_PEM"
        fake_addr = ('127.0.0.1', 12345)

        keyserver.handle_client(mock_socket, fake_addr)

        self.assertIn("8001", keyserver.public_keys)
        self.assertEqual(keyserver.public_keys["8001"], b"FAKE_PUBLIC_KEY_PEM")

        mock_socket.sendall.assert_called_with(b"Registration successful")

    def test_handle_client_getkey_success(self):
        keyserver.public_keys["8002"] = b"STORED_KEY_DATA"

        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"GETKEY|8002"
        fake_addr = ('127.0.0.1', 12345)

        keyserver.handle_client(mock_socket, fake_addr)

        mock_socket.sendall.assert_called_with(b"STORED_KEY_DATA")

    def test_handle_client_getkey_not_found(self):

        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"GETKEY|9999"
        fake_addr = ('127.0.0.1', 12345)

        keyserver.handle_client(mock_socket, fake_addr)

        mock_socket.sendall.assert_called_with(b"KEY_NOT_FOUND")

    def test_handle_client_unknown_command(self):
        mock_socket = MagicMock()
        mock_socket.recv.return_value = b"UNKNOWN|8001"
        fake_addr = ('127.0.0.1', 12345)

        keyserver.handle_client(mock_socket, fake_addr)

        mock_socket.sendall.assert_called_with(b"Unknown command")

if __name__ == '__main__':
    unittest.main()