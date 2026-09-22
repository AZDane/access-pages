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
    def test_route_identifiers_are_opaque_and_ambiguous_verification_is_deferred(self):
        for page in ('static', 'camera', 'api', 'health', 'verification', 'g', 'access'):
            root = f'/g/{page}/grant_aaaaaaaaaaaaaaaa/'
            self.assertEqual(diagnostics.guest_operation('GET', root), 'document')
            self.assertEqual(diagnostics.guest_operation('GET', root, True), 'bootstrap')
            self.assertEqual(diagnostics.guest_operation('GET', root + 'static/access.js'), 'asset')
            api = root + 'api/access/' + page
            self.assertEqual(diagnostics.guest_operation('GET', api), 'state')
            for resource in ('static', 'camera', 'state', 'action', 'api', 'health', 'verification'):
                self.assertEqual(diagnostics.guest_operation('GET', api + '/camera/' + resource), 'camera')
                for action in ('static', 'camera', 'state', 'action', 'turn_on'):
                    self.assertEqual(diagnostics.guest_operation('POST', api + '/' + resource + '/' + action), 'action')
            for action in ('send', 'verify'):
                self.assertEqual(diagnostics.guest_operation('POST', api + '/verification/' + action), 'other')
        self.assertEqual(diagnostics.guest_operation('GET', '/static/access.js'), 'asset')

    def test_diagnostic_operation_cannot_remove_or_add_action_authority(self):
        timing = diagnostics.RequestTiming('a' * 32, 1_000_000_000, 'other')
        headers = Message()
        for line in timing.headers(2_000_000_000).strip().split('\r\n'):
            name, value = line.split(': ', 1)
            headers[name] = value
        for category in ('state', 'asset', 'camera', 'unknown-private-name'):
            headers.replace_header(diagnostics.OPERATION, category)
            with patch('guest_diagnostics.clock_ns', return_value=10_000_000_000):
                received = diagnostics.timing_from_headers(headers, 'action', required=True, internal_rpc=True)
                token = diagnostics.CURRENT.set(received)
                try:
                    with self.assertRaises(diagnostics.ActionDeadlineExceeded):
                        diagnostics.action_remaining(20)
                finally:
                    diagnostics.CURRENT.reset(token)
        headers.replace_header(diagnostics.OPERATION, 'action')
        with patch('guest_diagnostics.clock_ns', return_value=10_000_000_000):
            received = diagnostics.timing_from_headers(headers, 'other', internal_rpc=True)
            self.assertFalse(received.action_deadline)

    def test_state_buffer_keeps_normal_success_quiet_and_retains_interesting_history(self):
        for trigger in ('normal', 'slow', 'queue', 'denied', 'disconnect', 'drops'):
            with self.subTest(trigger=trigger):
                records = []
                now = [1_000_000_000]
                timing = diagnostics.RequestTiming('b' * 32, now[0], 'state')
                token = diagnostics.CURRENT.set(timing)
                try:
                    with (patch.object(diagnostics.SINK, 'emit', side_effect=records.append),
                          patch('guest_diagnostics.clock_ns', side_effect=lambda: now[0])):
                        diagnostics.emit('guest_service_received', 'guest_service')
                        diagnostics.emit('broker_rpc_sent', 'guest_service')
                        self.assertEqual(records, [])
                        if trigger == 'slow':
                            now[0] += 300_000_000
                        if trigger == 'drops':
                            timing.trace.dropped -= 1
                        diagnostics.emit('broker_request_started', 'ha_broker',
                                         broker_wait_ns=150_000_000 if trigger == 'queue' else 1000)
                        diagnostics.emit('guest_response_written', 'guest_service',
                                         status=403 if trigger == 'denied' else 200,
                                         outcome='disconnected' if trigger == 'disconnect' else 'success')
                        diagnostics.finish()
                        self.assertEqual(len(timing.trace.records), 0)
                        self.assertEqual(len(records), 0 if trigger == 'normal' else 4)
                finally:
                    diagnostics.CURRENT.reset(token)

    def test_stage_transfer_is_bounded_numeric_and_malformed_data_never_rejects(self):
        timing = diagnostics.RequestTiming('c' * 32, diagnostics.clock_ns(), 'state')
        token = diagnostics.CURRENT.set(timing)
        self.addCleanup(diagnostics.CURRENT.reset, token)
        for value in (None, 'cookie=private', '1,' * 10000, '1,2,3,4,5,600000001,1'):
            diagnostics.receive_stages(value)
        self.assertEqual(timing.trace.stages, [-1] * 6)
        diagnostics.receive_stages('-1,-1,100,120,200,50,0')
        self.assertEqual(diagnostics.stage_header(), '-1,-1,100,120,200,50,0')
        records = []
        with patch.object(diagnostics.SINK, 'emit', side_effect=records.append):
            diagnostics.emit('guest_service_received', 'guest_service')
            diagnostics.receive_stages('-1,-1,100,120,200,50,1')
        self.assertEqual(len(records), 1)
        self.assertTrue(timing.trace.interesting)

    def test_lifetime_is_unchanged_by_rpc_and_ignores_wall_clock(self):
        timing = diagnostics.RequestTiming('a' * 32, 1_000_000_000, 'action', action_deadline=True)
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
        timing = diagnostics.RequestTiming('a' * 32, 1_000_000_000, 'action', action_deadline=True)
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
        dropped = sink.dropped
        sink.emit({'event': 'recovered'})
        sink.queue.join()
        self.assertEqual(json.loads(lines[-1])['dropped_events'], dropped)
        self.assertTrue(all('process_id' in json.loads(line) for line in lines))
