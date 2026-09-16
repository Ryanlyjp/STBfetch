import os
import signal
import unittest
from unittest.mock import patch

import flaresolverr_service
from dtos import V1RequestBase


class FakeConnection:
    def __init__(self, polls, messages):
        self.polls = iter(polls)
        self.messages = iter(messages)
        self.closed = False

    def poll(self, _timeout):
        return next(self.polls)

    def recv(self):
        return next(self.messages)

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self):
        self.pid = 12345
        self.started = False
        self.alive = True

    def start(self):
        self.started = True

    def is_alive(self):
        return self.alive

    def join(self, _timeout):
        return None

    def terminate(self):
        self.alive = False

    def kill(self):
        self.alive = False


class FakeContext:
    def __init__(self, receiver, sender, process):
        self.receiver = receiver
        self.sender = sender
        self.process = process

    def Pipe(self, duplex=False):
        self.duplex = duplex
        return self.receiver, self.sender

    def Process(self, target, args):
        self.target = target
        self.args = args
        return self.process


class CamoufoxLifecycleTests(unittest.TestCase):
    def test_timeout_always_terminates_worker_and_removes_registration(self):
        receiver = FakeConnection([True, False], [('ready', None)])
        sender = FakeConnection([], [])
        process = FakeProcess()
        context = FakeContext(receiver, sender, process)
        request = V1RequestBase({
            'requestId': 'request-timeout',
            'maxTimeout': 1000,
        })

        with patch.object(flaresolverr_service, 'CAMOUFOX_PROCESS_CONTEXT', context), patch.object(
            flaresolverr_service, '_terminate_camoufox_worker'
        ) as terminate, patch.object(
            flaresolverr_service.tempfile, 'mkdtemp', return_value='/tmp/camoufox-task-test'
        ), patch.object(flaresolverr_service.shutil, 'rmtree') as remove_tree:
            with self.assertRaisesRegex(Exception, 'timed out'):
                flaresolverr_service._resolve_camoufox_isolated(request)

        terminate.assert_called_once_with(process)
        self.assertNotIn('request-timeout', flaresolverr_service.CAMOUFOX_WORKERS)
        self.assertTrue(receiver.closed)
        self.assertTrue(sender.closed)
        remove_tree.assert_called_once_with('/tmp/camoufox-task-test', ignore_errors=True)

    def test_cancel_command_terminates_registered_worker(self):
        process = FakeProcess()
        flaresolverr_service.CAMOUFOX_WORKERS['request-cancel'] = process
        request = V1RequestBase({
            'requestId': 'request-cancel',
        })

        try:
            with patch.object(flaresolverr_service, '_terminate_camoufox_worker') as terminate:
                response = flaresolverr_service._cmd_request_cancel(request)
        finally:
            flaresolverr_service.CAMOUFOX_WORKERS.pop('request-cancel', None)

        terminate.assert_called_once_with(process)
        self.assertEqual(response.status, 'ok')
        self.assertEqual(response.message, 'Camoufox request cancelled.')

    def test_worker_process_group_escalates_to_sigkill(self):
        process = FakeProcess()
        signals = []

        def kill_group(_pid, sent_signal):
            signals.append(sent_signal)
            if sent_signal == signal.SIGKILL:
                process.alive = False

        with patch.object(os, 'getpgid', return_value=process.pid), patch.object(
            os, 'killpg', side_effect=kill_group
        ):
            flaresolverr_service._terminate_camoufox_worker(process)

        self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL])


if __name__ == '__main__':
    unittest.main()
