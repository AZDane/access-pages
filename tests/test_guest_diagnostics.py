"""Privacy, nonblocking logging and monotonic action lifetime boundaries."""
from email.message import Message
import unittest
from unittest.mock import MagicMock, patch

import guest_request as request
from ha import HomeAssistantClient


class GuestTimingTests(unittest.TestCase):
    def test_route_identifiers_are_opaque_and_ambiguous_verification_is_deferred(self):
        for page in ('static', 'camera', 'api', 'health', 'verification', 'g', 'access'):
            root = f'/g/{page}/grant_aaaaaaaaaaaaaaaa/'
            self.assertEqual(request.guest_operation('GET', root), 'document')
            self.assertEqual(request.guest_operation('GET', root, True), 'bootstrap')
            self.assertEqual(request.guest_operation('GET', root + 'static/access.js'), 'asset')
            api = root + 'api/access/' + page
            self.assertEqual(request.guest_operation('GET', api), 'state')
            for resource in ('static', 'camera', 'state', 'action', 'api', 'health', 'verification'):
                self.assertEqual(request.guest_operation('GET', api + '/camera/' + resource), 'camera')
                for action in ('static', 'camera', 'state', 'action', 'turn_on'):
                    self.assertEqual(request.guest_operation('POST', api + '/' + resource + '/' + action), 'action')
            for action in ('send', 'verify'):
                self.assertEqual(request.guest_operation('POST', api + '/verification/' + action), 'other')
        self.assertEqual(request.guest_operation('GET', '/static/access.js'), 'asset')

    def test_diagnostic_operation_cannot_remove_or_add_action_authority(self):
        timing = request.RequestTiming('a' * 32, 1_000_000_000, 'other')
        headers = Message()
        for line in timing.headers().strip().split('\r\n'):
            name, value = line.split(': ', 1)
            headers[name] = value
        for category in ('state', 'asset', 'camera', 'unknown-private-name'):
            headers.replace_header(request.OPERATION, category)
            with patch('guest_request.clock_ns', return_value=10_000_000_000):
                received = request.timing_from_headers(headers, 'action', required=True, internal_rpc=True)
                token = request.CURRENT.set(received)
                try:
                    with self.assertRaises(request.ActionDeadlineExceeded):
                        request.action_remaining(20)
                finally:
                    request.CURRENT.reset(token)
        headers.replace_header(request.OPERATION, 'action')
        with patch('guest_request.clock_ns', return_value=10_000_000_000):
            received = request.timing_from_headers(headers, 'other', internal_rpc=True)
            self.assertFalse(received.action_deadline)

    def test_lifetime_is_unchanged_by_rpc_and_ignores_wall_clock(self):
        timing = request.RequestTiming('a' * 32, 1_000_000_000, 'action', action_deadline=True)
        headers = Message()
        for line in timing.headers().strip().split('\r\n'):
            name, value = line.split(': ', 1)
            headers[name] = value
        with patch('guest_request.clock_ns', return_value=4_000_000_000):
            received = request.timing_from_headers(headers, 'other', internal_rpc=True)
            self.assertEqual(received.started_ns, timing.started_ns)
            self.assertEqual(received.remaining(), 5)
        with patch('guest_request.clock_ns', return_value=9_000_000_000):
            with self.assertRaises(request.ActionDeadlineExceeded):
                received.remaining()

    def test_missing_duplicate_future_or_malformed_metadata_rejected(self):
        for values in ({}, {request.REQUEST_ID: 'cookie=secret'},
                       {request.STARTED_NS: '9999999999999999999'},
                       {request.STARTED_NS: '-1'}):
            headers = Message()
            if values:
                headers[request.REQUEST_ID] = 'a' * 32
                headers[request.STARTED_NS] = str(request.clock_ns())
                for name, value in values.items():
                    if name in headers:
                        del headers[name]
                    headers[name] = value
            with self.assertRaises(ValueError):
                request.timing_from_headers(headers, 'action', required=True)
        headers = Message()
        headers[request.REQUEST_ID] = 'a' * 32
        headers[request.REQUEST_ID] = 'b' * 32
        headers[request.STARTED_NS] = str(request.clock_ns())
        with self.assertRaises(ValueError):
            request.timing_from_headers(headers, 'state')

    def test_ha_final_boundary_never_posts_expired_work_and_caps_timeout(self):
        client = HomeAssistantClient('http://ha.invalid', 'synthetic-private-ha-token')
        timing = request.RequestTiming('a' * 32, 1_000_000_000, 'action', action_deadline=True)
        token = request.CURRENT.set(timing)
        self.addCleanup(request.CURRENT.reset, token)
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b'[]'
        with (patch('ha.urlopen', return_value=response) as post,
              patch('guest_request.clock_ns', return_value=8_000_000_000)):
            client.call_service('switch', 'turn_on', 'switch.private')
            self.assertEqual(post.call_args.kwargs['timeout'], 1)
        with (patch('ha.urlopen') as post,
              patch('guest_request.clock_ns', return_value=9_000_000_000)):
            with self.assertRaises(request.ActionDeadlineExceeded):
                client.call_service('switch', 'turn_on', 'switch.private')
            post.assert_not_called()

    def test_broker_disconnect_records_evidence_and_always_resets_context(self):
        import ha_broker
        outer = request.RequestTiming('a' * 32, request.clock_ns(), 'state')
        token = request.CURRENT.set(outer)
        self.addCleanup(request.CURRENT.reset, token)
        handler = object.__new__(ha_broker.GuestHandler)
        handler.path = '/guest/v1/page'
        handler.headers = Message()
        for line in outer.headers().strip().split('\r\n'):
            name, value = line.split(': ', 1)
            handler.headers[name] = value
        for error in (BrokenPipeError, ConnectionResetError):
            for logging_fails in (False, True):
                with self.subTest(error=error, logging_fails=logging_fails):
                    def record(*args, **kwargs):
                        self.assertIsNot(request.CURRENT.get(), outer)
                        self.assertEqual(request.CURRENT.get().stages[11], 4)
                        if logging_fails:
                            raise RuntimeError('synthetic observer failure')
                    with (patch.object(handler, '_scoped_POST', side_effect=error),
                          patch.object(ha_broker.diagnostics, 'record', side_effect=record) as observe):
                        if logging_fails:
                            with self.assertRaises(RuntimeError):
                                handler.do_POST()
                        else:
                            handler.do_POST()
                        observe.assert_called_once_with('broker', status=None)
                    self.assertTrue(handler.close_connection)
                    self.assertIs(request.CURRENT.get(), outer)



class MinimalObservabilityTests(unittest.TestCase):
    def setUp(self):
        import guest_diagnostics
        self.d = guest_diagnostics
        self.now = [10_000_000_000]
        self.clock = patch('guest_request.clock_ns', side_effect=lambda: self.now[0])
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.mode = patch.object(self.d, 'DETAIL_UNTIL', 0)
        self.mode.start()
        self.addCleanup(self.mode.stop)
        self.timing = request.RequestTiming('c' * 32, self.now[0], 'state')
        token = request.CURRENT.set(self.timing)
        self.addCleanup(request.CURRENT.reset, token)

    def test_normal_success_constructs_no_records_or_history(self):
        with patch.object(self.d.SINK, 'emit') as emit:
            for _ in range(1200):
                for index in range(7):
                    self.d.boundary(index, 'service')
                with self.d.ha_request():
                    pass
            emit.assert_not_called()
        self.assertEqual(len(self.timing.stages), 12)
        self.assertFalse(hasattr(self.timing, 'trace'))

    def test_numeric_transport_accumulates_bounded_calls_without_private_data(self):
        for value in (None, 'cookie=private', '1,' * 10000, '1,2,3,4,5,600001,7,1,2,1,1,0'):
            self.d.receive_stages(value)
        self.assertEqual(self.timing.stages, [-1] * 7 + [0, 0, 0, 1, 0])
        self.d.receive_stages('-1,-1,3,4,5,6,-1,2,10,0,1,0')
        self.d.receive_stages('-1,-1,7,8,9,10,-1,3,20,0,1,0')
        self.assertEqual(self.timing.stages[2:6], [3, 4, 9, 10])
        self.assertEqual(self.timing.stages[7:9], [5, 30])
        self.assertLess(len(self.d.stage_header()), 97)

    def test_detailed_boundaries_expire_and_do_not_generate_requests(self):
        from unittest.mock import Mock
        records = []
        with (patch.object(self.d, 'DETAIL_UNTIL', self.now[0] + 1_000_000_000),
              patch.object(self.d.SINK, 'emit', side_effect=lambda r, **kw: records.append(r)),
              patch('ha.urlopen') as network):
            response = Mock()
            response.read.return_value = b'[]'
            network.return_value.__enter__.return_value = response
            self.d.boundary(0, 'service')
            HomeAssistantClient('http://ha.invalid', 'synthetic').get_states()
            self.assertEqual(network.call_count, 1)
            self.assertEqual([r['at'] for r in records], ['0', '3', '4'])
            self.now[0] += 1_000_000_000
            self.d.boundary(6, 'service')
            self.assertEqual(len(records), 3)
            HomeAssistantClient('http://ha.invalid', 'synthetic').get_states()
            self.assertEqual(network.call_count, 2)
            self.assertEqual(len(records), 3)

    def test_dispatched_but_unconfirmed_is_uncertain_and_not_replayed(self):
        import json
        from urllib.error import URLError
        from ha import HomeAssistantError
        self.timing.operation = 'action'
        self.timing.action_deadline = True
        records = []
        with (patch.object(self.d.SINK, 'emit', side_effect=lambda r, **kw: records.append(r)),
              patch('ha.urlopen', side_effect=URLError(TimeoutError('private token body email'))) as post):
            with self.assertRaises(HomeAssistantError):
                HomeAssistantClient('http://private.invalid', 'private-token').call_service('switch', 'turn_on', 'switch.private')
            self.d.record('broker', status=502)
        post.assert_called_once()
        self.assertEqual(records[-1]['outcome'], 'uncertain')
        self.assertEqual(records[-1]['v'][10], 2)
        self.assertNotIn('private', json.dumps(records))
        self.assertNotIn('email', json.dumps(records))

    def test_token_budget_exact_sustained_bounds(self):
        for detail, expected in ((False, 60), (True, 1811)):
            budget = self.d.Budget()
            # 1000 offered events/second over one hour, excluding the endpoint.
            admitted = sum(budget.take(n * 1_000_000, detail) for n in range(3_600_000))
            self.assertEqual(admitted, expected)

    def test_blocked_output_queue_overflow_loss_and_expiration(self):
        import json
        import threading
        import time
        entered, release = threading.Event(), threading.Event()
        lines = []
        def write(line):
            entered.set()
            release.wait(5)
            lines.append(line)
        sink = self.d.DiagnosticSink(write=write)
        try:
            with patch.object(self.d, 'DETAIL_UNTIL', self.now[0] + 1000_000_000_000):
                sink.emit({'at': 'end'})
                self.assertTrue(entered.wait(1))
                start = time.monotonic()
                for _ in range(1000):
                    self.now[0] += 2_000_000_000
                    sink.emit({'at': 'end'}, detail=True)
                self.assertLess(time.monotonic() - start, .5)
                self.assertEqual(sink.queue.qsize(), 16)
                self.assertGreater(sink.lost, 900)
            release.set()
            sink.queue.join()
            self.assertEqual(len(lines), 1)  # Queued detail expired while output blocked.
            self.now[0] += 60_000_000_000
            sink.emit({'at': 'end'})
            sink.queue.join()
            self.assertGreater(json.loads(lines[-1])['lost'], 900)
            self.assertTrue(all(len(line.encode()) <= 512 for line in lines))
        finally:
            release.set()

    def test_worker_output_rate_and_oversize_are_bounded(self):
        lines = []
        sink = self.d.DiagnosticSink(write=lines.append)
        for _ in range(10000):
            sink._write({'at': 'loss'})
        self.assertEqual(len(lines), 1)
        self.now[0] += 60_000_000_000
        sink._write({'bad': 'x' * 513})
        self.assertEqual(len(lines), 1)
        self.assertGreaterEqual(sink.lost, 10000)

    def test_blocked_write_time_does_not_refill_the_output_budget(self):
        lines = []
        def write(line):
            lines.append(line)
            self.now[0] += 120_000_000_000  # Writer returns after a long blockage.
        sink = self.d.DiagnosticSink(write=write)
        sink._write({'at': 'loss'})
        sink._write({'at': 'loss'})
        self.assertEqual(len(lines), 1)
        self.assertEqual(sink.lost, 1)
