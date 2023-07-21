from pathlib import Path
from unittest import TestCase, mock
from unittest.mock import patch, mock_open, call

import yaml

from packet_hunter import PacketHunter


class TestHunter(TestCase):
    DEFAULT_CONFIG = {
        'first': {'filter': 'value_1'},
        'second': {'filter': 'value_2'},
        'third': {'filter': 'value_3'}
    }

    @classmethod
    @patch('os.path.exists')
    @patch('builtins.open', mock_open(read_data='1'))
    @patch.object(Path, 'mkdir')
    @patch.object(yaml, 'safe_load')
    def setUpClass(cls, mock_yaml, mock_dir, mock_path):
        mock_path.side_effect = [True, True]
        mock_dir.return_value = 0

        mock_yaml.return_value = TestHunter.DEFAULT_CONFIG

        with patch('__main__.open'):
            cls.hunter = PacketHunter("source", "destination", "config")

    @patch('os.path.exists')
    @patch('builtins.open', mock_open(read_data='1'))
    @patch.object(Path, 'mkdir')
    @patch.object(yaml, 'safe_load')
    def test_read_filters(self, mock_yaml, mock_dir, mock_path):
        self.assertEqual(3, len(self.hunter.filters))

        assert True

    @patch('os.path.exists')
    @patch('builtins.open', mock_open(read_data='1'))
    @patch.object(Path, 'mkdir')
    @patch.object(yaml, 'safe_load')
    def test_read_filters_override(self, mock_yaml, mock_dir, mock_path):
        mock_path.side_effect = [True, True]
        mock_dir.return_value = 0

        mock_yaml.return_value = TestHunter.DEFAULT_CONFIG

        with patch('__main__.open'):
            hunter = PacketHunter("source", "destination", "config", ["first", "third"])

        self.assertEqual(2, len(hunter.filters))
        self.assertEqual("first", hunter.filters[0].name)
        self.assertEqual("third", hunter.filters[1].name)

        assert True

    @patch('os.path.exists')
    @patch('builtins.open', mock_open(read_data='1'))
    @patch.object(Path, 'mkdir')
    @patch.object(yaml, 'safe_load')
    def test_read_filters_invalid_override(self, mock_yaml, mock_dir, mock_path):
        mock_path.side_effect = [True, True]
        mock_dir.return_value = 0

        mock_yaml.return_value = TestHunter.DEFAULT_CONFIG

        with patch('__main__.open'):
            hunter = PacketHunter("source", "destination", "config", ["first", "missing"])

        self.assertEqual(1, len(hunter.filters))
        self.assertEqual("first", hunter.filters[0].name)

        assert True

    @patch('subprocess.run')
    def test_extract_filter(self, mock_process):
        self.hunter.extract_filter("source")
        source_path = f"source-{self.hunter.date_time}"
        expected_calls = [
            call(["tshark", "-r", "source", "-Y", "value_1", "-w", Path(f"destination/first/" + source_path)]),
            call(["tshark", "-r", "source", "-Y", "value_2", "-w", Path(f"destination/second/" + source_path)]),
            call(["tshark", "-r", "source", "-Y", "value_3", "-w", Path(f"destination/third/" + source_path)])
        ]

        mock_process.assert_has_calls(expected_calls)

    @patch('subprocess.run')
    @patch.object(Path, 'unlink')
    @patch.object(Path, 'glob')
    def test_merge_filters(self, mock_glob, mock_unlink, mock_process):
        mock_unlink.return_value = 0
        mock_glob.return_value = ["first", "second"]
        self.hunter.merge_filters()

        destination = f"{self.hunter.date_time}.pcapng"
        expected_calls = [
            call(["mergecap", "-w", Path(f"destination/first/all-first-" + destination), "first", "second"]),
            call(["mergecap", "-w", Path(f"destination/second/all-second-" + destination), "first", "second"]),
            call(["mergecap", "-w", Path(f"destination/third/all-third-" + destination), "first", "second"])
        ]

        mock_process.assert_has_calls(expected_calls)


