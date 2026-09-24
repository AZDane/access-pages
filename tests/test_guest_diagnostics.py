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

    def test_utc_observation_survives_queue_delay_and_wall_clock_jumps(self):
        from datetime import datetime, timezone
        import json
        import threading
        entered, release = threading.Event(), threading.Event()
        records = []
        def write(line):
            entered.set()
            release.wait(5)
            records.append(json.loads(line))
        sink = self.d.DiagnosticSink(write=write)
        try:
            with (patch.object(self.d, 'DETAIL_UNTIL', self.now[0] + 1_000_000_000),
                  patch.object(self.d, 'datetime') as wall):
                for year, at in ((2026, '1'), (2036, '3'), (2016, 'end')):
                    wall.now.return_value = datetime(year, 9, 24, 0, 8, 54, 123456, timezone.utc)
                    sink.emit({'at': at})
                    self.assertTrue(entered.wait(1))
                    self.assertEqual(self.timing.remaining(), 8)
                    self.assertEqual(self.d.offset(self.timing), 0)
                    self.assertTrue(self.d.detailed())
                self.assertEqual(sink.admission.tokens, 9)
                # Both future and past wall clocks leave the monotonic deadline intact.
                self.now[0] += 8_000_000_000
                self.assertFalse(self.d.detailed())
                with self.assertRaises(request.ActionDeadlineExceeded):
                    self.timing.remaining()
                # Keep detailed output allowance while draining this queue test.
                self.now[0] -= 8_000_000_000
                release.set()
                sink.queue.join()
            self.assertEqual([r['timestamp'] for r in records], [
                f'{year}-09-24T00:08:54.123Z' for year in (2026, 2036, 2016)])
            self.assertEqual(sink.output.tokens, 9)
        finally:
            release.set()

    def test_idle_loss_report_has_utc_timestamp(self):
        import json
        from queue import Empty
        from datetime import datetime
        lines = []
        sink = self.d.DiagnosticSink(write=lines.append)
        sink.lose()
        with patch.object(sink.queue, 'get', side_effect=[Empty, RuntimeError('stop test worker')]):
            with self.assertRaisesRegex(RuntimeError, 'stop test worker'):
                sink._run()
        record = json.loads(lines[0])
        self.assertEqual((record['at'], record['lost']), ('loss', 1))
        datetime.strptime(record['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
        self.assertEqual(len(record['timestamp']), 24)

    def test_maximum_diagnostic_with_timestamp_still_fits_record_bound(self):
        import json
        lines = []
        sink = self.d.DiagnosticSink(write=lines.append)
        sink.lost = self.d.COUNTER_MAX
        self.timing.request_id = 'f' * 32
        self.timing.operation = 'verification'
        self.timing.action_deadline = True
        self.timing.stages = [self.d.LIMIT] * 10 + [2, 7]
        self.now[0] += self.d.LIMIT * 1_000_000
        with patch.object(self.d, 'SINK', sink), patch.object(self.d.os, 'getpid', return_value=2147483647):
            self.d.record('service', status=599)
            sink.queue.join()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record['outcome'], 'uncertain')
        self.assertEqual(record['ms'], self.d.LIMIT)
        self.assertEqual(len(record['timestamp']), 24)
        self.assertLessEqual(len(lines[0].encode()), 512)

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
        self.timing.request_id = 'c' * 31 + '0'
        records = []
        with (patch.object(self.d, 'DETAIL_UNTIL', self.now[0] + 1_000_000_000),
              patch.object(self.d.SINK, 'emit', side_effect=lambda r, **kw: records.append(r)),
              patch('ha.urlopen') as network):
            response = Mock()
            response.read.return_value = b'[]'
            network.return_value.__enter__.return_value = response
            self.d.boundary(0, 'service')
            self.d.boundary(1, 'service')
            HomeAssistantClient('http://ha.invalid', 'synthetic').get_states()
            self.assertEqual(network.call_count, 1)
            self.assertEqual([r['at'] for r in records], ['1', '3'])
            self.assertGreaterEqual(self.timing.stages[4], 0)
            self.now[0] += 1_000_000_000
            self.d.boundary(6, 'service')
            self.assertEqual(len(records), 2)
            HomeAssistantClient('http://ha.invalid', 'synthetic').get_states()
            self.assertEqual(network.call_count, 2)
            self.assertEqual(len(records), 2)

    def test_unselected_boundaries_retain_vector_without_emission_or_loss(self):
        with (patch.object(self.d, 'DETAIL_UNTIL', self.now[0] + 1_000_000_000),
              patch.object(self.d.SINK, 'emit') as emit):
            for index in range(7):
                self.d.boundary(index, 'service')
                self.now[0] += 1_000_000
            emit.assert_not_called()
            self.assertEqual(self.timing.stages[:7], list(range(7)))

    def test_detailed_rpc_and_ha_failures_are_not_sampled_or_expired_as_detail(self):
        from urllib.error import URLError
        from ha import HomeAssistantError
        with (patch.object(self.d, 'DETAIL_UNTIL', self.now[0] + 1_000_000_000),
              patch.object(self.d.SINK, 'emit') as emit,
              patch('ha.urlopen', side_effect=URLError(TimeoutError('private')))):
            self.d.failure(6, 'service')
            self.assertEqual(emit.call_args.args[0]['v'][11], 6)
            self.assertFalse(emit.call_args.kwargs['detail'])
            with self.assertRaises(HomeAssistantError):
                HomeAssistantClient('http://ha.invalid', 'synthetic').get_states()
            record = emit.call_args.args[0]
            self.assertEqual(record['part'], 'ha')
            self.assertEqual(record['outcome'], 'error')
            self.assertGreaterEqual(record['v'][4], record['v'][3])
            self.assertFalse(emit.call_args.kwargs['detail'])

    def test_selected_request_leaves_evidence_before_blocked_ha_returns(self):
        import json
        import threading
        entered, release, written = threading.Event(), threading.Event(), threading.Event()
        records = []
        def write(line):
            records.append(json.loads(line))
            if records[-1].get('part') == 'ha':
                written.set()
        sink = self.d.DiagnosticSink(write=write)
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'[]'
        def network(*args, **kwargs):
            entered.set()
            release.wait(5)
            return response
        self.timing.request_id = 'c' * 31 + '0'
        def run():
            token = request.CURRENT.set(self.timing)
            try:
                self.d.boundary(1, 'service')
                HomeAssistantClient('http://ha.invalid', 'synthetic').get_states()
            finally:
                request.CURRENT.reset(token)
        with (patch.object(self.d, 'DETAIL_UNTIL', self.now[0] + 1_000_000_000),
              patch.object(self.d, 'SINK', sink), patch('ha.urlopen', side_effect=network)):
            worker = threading.Thread(target=run)
            worker.start()
            try:
                self.assertTrue(entered.wait(1))
                self.assertTrue(written.wait(1))
                self.assertTrue(worker.is_alive())
                self.assertEqual([r['at'] for r in records], ['1', '3'])
                self.assertEqual(records[-1]['v'][4], -1)
                self.assertEqual({r['id'] for r in records}, {self.timing.request_id})
            finally:
                release.set()
                worker.join(2)
                sink.queue.join()
            self.assertFalse(worker.is_alive())
            self.assertGreaterEqual(self.timing.stages[4], 0)
            self.assertEqual(len(records), 2)

    def test_unsampled_action_denial_is_recorded_before_response_write(self):
        import guest_service
        import ha_broker
        self.timing.operation = 'action'
        self.timing.action_deadline = True
        self.timing.stages[11] = 3
        for dispatch, outcome in ((1, 'deadline'), (2, 'uncertain')):
            self.timing.stages[10] = dispatch
            for cls, method, args in (
                    (guest_service.GuestHandler, '_send', (503, b'{}', 'application/json')),
                    (ha_broker.GuestHandler, '_send_denial', (503, 'action_deadline'))):
                handler = object.__new__(cls)
                with (patch.object(self.d, 'DETAIL_UNTIL', self.now[0] + 1_000_000_000),
                      patch.object(self.d.SINK, 'emit') as emit):
                    def stop_write(*args):
                        self.assertEqual(emit.call_args.args[0]['outcome'], outcome)
                        self.assertFalse(emit.call_args.kwargs['detail'])
                        raise TimeoutError('synthetic blocked response')
                    with patch.object(handler, 'send_response', side_effect=stop_write):
                        with self.assertRaises(TimeoutError):
                            getattr(handler, method)(*args)

    def test_sampled_observations_leave_output_allowance_for_abnormal_records(self):
        import json
        lines = []
        sink = self.d.DiagnosticSink(write=lines.append)
        with patch.object(self.d, 'DETAIL_UNTIL', self.now[0] + 1_000_000_000):
            for _ in range(100):
                sink._write({'at': '3'}, detail=True)
            self.assertEqual(len(lines), 6)
            for _ in range(6):
                sink._write({'at': 'end', 'outcome': 'uncertain'})
            self.assertEqual(len(lines), 12)
            self.assertEqual(json.loads(lines[-1])['outcome'], 'uncertain')
            self.assertEqual(json.loads(lines[-1])['lost'], 94)

    def test_sampled_observations_leave_queue_capacity_for_abnormal_records(self):
        import threading
        entered, release = threading.Event(), threading.Event()
        def write(line):
            entered.set()
            release.wait(5)
        sink = self.d.DiagnosticSink(write=write)
        try:
            with patch.object(self.d, 'DETAIL_UNTIL', self.now[0] + 3600_000_000_000):
                sink.emit({'at': '1'}, detail=True)
                self.assertTrue(entered.wait(1))
                for _ in range(100):
                    self.now[0] += 3_000_000_000
                    sink.emit({'at': '1'}, detail=True)
                self.assertEqual(sink.queue.qsize(), 8)
                for _ in range(8):
                    self.now[0] += 3_000_000_000
                    sink.emit({'at': 'end', 'outcome': 'error'})
                self.assertEqual(sink.queue.qsize(), 16)
        finally:
            release.set()
            sink.queue.join()

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
                self.assertEqual(sink.queue.qsize(), 8)
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
