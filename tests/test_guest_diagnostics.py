"""Privacy, nonblocking logging and monotonic action lifetime boundaries."""
from email.message import Message
import json
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import guest_diagnostics as diagnostics
from ha import HomeAssistantClient, HomeAssistantError


class GuestTimingTests(unittest.TestCase):
    def test_lifetime_is_unchanged_by_rpc_and_ignores_wall_clock(self):
        timing = diagnostics.RequestTiming('a' * 32, 1_000_000_000, 'action')
        headers = Message()
        for line in timing.headers(3_000_000_000).strip().split('\r\n'):
            name, value = line.split(': ', 1)
            headers[name] = value
        with patch('guest_diagnostics.clock_ns', return_value=4_000_000_000):
            received = diagnostics.timing_from_headers(headers, 'other', internal_rpc=True)
            self.assertEqual(received.started_ns, timing.started_ns)
            self.assertEqual(received.remaining(), 5)
        with patch('guest_diagnostics.clock_ns', return_value=9_000_000_000):
            with self.assertRaises(diagnostics.ActionDeadlineExceeded):
                received.remaining()

    def test_missing_duplicate_future_or_malformed_metadata_rejected(self):
        for values in ({}, {diagnostics.REQUEST_ID: 'cookie=secret'},
                       {diagnostics.STARTED_NS: '9999999999999999999'},
                       {diagnostics.STARTED_NS: '-1'},
                       {diagnostics.RPC_STARTED_NS: '1'}):
            headers = Message()
            if values:
                headers[diagnostics.REQUEST_ID] = 'a' * 32
                headers[diagnostics.STARTED_NS] = str(diagnostics.clock_ns())
                for name, value in values.items():
                    if name in headers:
                        del headers[name]
                    headers[name] = value
            with self.assertRaises(ValueError):
                diagnostics.timing_from_headers(headers, 'action', required=True)
        headers = Message()
        headers[diagnostics.REQUEST_ID] = 'a' * 32
        headers[diagnostics.REQUEST_ID] = 'b' * 32
        headers[diagnostics.STARTED_NS] = str(diagnostics.clock_ns())
        with self.assertRaises(ValueError):
            diagnostics.timing_from_headers(headers, 'state')

    def test_ha_final_boundary_never_posts_expired_work_and_caps_timeout(self):
        client = HomeAssistantClient('http://ha.invalid', 'synthetic-private-ha-token')
        timing = diagnostics.RequestTiming('a' * 32, 1_000_000_000, 'action')
        token = diagnostics.CURRENT.set(timing)
        self.addCleanup(diagnostics.CURRENT.reset, token)
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b'[]'
        with (patch('ha.urlopen', return_value=response) as post,
              patch('guest_diagnostics.clock_ns', return_value=8_000_000_000)):
            client.call_service('switch', 'turn_on', 'switch.private')
            self.assertEqual(post.call_args.kwargs['timeout'], 1)
        with (patch('ha.urlopen') as post,
              patch('guest_diagnostics.clock_ns', return_value=9_000_000_000)):
            with self.assertRaises(diagnostics.ActionDeadlineExceeded):
                client.call_service('switch', 'turn_on', 'switch.private')
            post.assert_not_called()

    def test_ha_timeout_diagnostics_are_correlated_and_contain_no_private_data(self):
        records = []
        timing = diagnostics.RequestTiming('b' * 32, diagnostics.clock_ns(), 'state')
        token = diagnostics.CURRENT.set(timing)
        self.addCleanup(diagnostics.CURRENT.reset, token)
        client = HomeAssistantClient('http://private-ha.invalid', 'private-ha-token')
        with (patch.object(diagnostics.SINK, 'emit', side_effect=records.append),
              patch('ha.urlopen', side_effect=URLError(TimeoutError('private state payload')))):
            with self.assertRaises(HomeAssistantError):
                client.get_states()
        self.assertEqual([r['event'] for r in records], ['ha_request_started', 'ha_response_completed'])
        self.assertEqual(records[-1]['outcome'], 'timeout')
        self.assertTrue(all(r['request_id'] == timing.request_id for r in records))
        self.assertIn('duration_ms', records[-1])
        encoded = json.dumps(records)
        for secret in ('private-ha', 'private state', 'Authorization', 'cookie', 'email', 'entity_id'):
            self.assertNotIn(secret, encoded)
        self.assertTrue(all(set(r) <= {
            'event', 'component', 'request_id', 'operation', 'outcome', 'timestamp',
            'elapsed_ms', 'duration_ms', 'ha_operation', 'status', 'status_class',
        } for r in records))

    def test_blocked_log_sink_never_blocks_request_thread(self):
        entered, release = threading.Event(), threading.Event()
        lines = []
        def write(line):
            entered.set()
            release.wait(5)
            lines.append(line)
        sink = diagnostics.DiagnosticSink(write=write, capacity=1)
        try:
            sink.emit({'event': 'fixture'})
            self.assertTrue(entered.wait(1))
            start = time.monotonic()
            for _ in range(1000):
                sink.emit({'event': 'fixture'})
            self.assertLess(time.monotonic() - start, .5)
            self.assertGreater(sink.dropped, 0)
            self.assertEqual(sink.queue.qsize(), 1)
        finally:
            release.set()
            sink.queue.join()
        self.assertTrue(all('process_id' in json.loads(line) for line in lines))
