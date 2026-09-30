"""Hosted boundaries exercised without network accounts or production records."""
import copy
import http.client
import json
import threading
import unittest
import uuid

from traceweave.hosted import COOKIE, HostedHandler, HostedServer, RemoteError, restore, snapshot


class MemoryStore:
    def __init__(self):
        self.rows = {}
        self.fail_save = False

    def request(self, path, token=None, body=None, method=None):
        if path == '/auth/v1/user' and token in ('alice', 'bob'):
            return {'id': token, 'email': token + '@example.invalid'}
        if path.startswith('/auth/v1/token'):
            return {'access_token': 'alice', 'expires_in': 3600}
        raise RemoteError('Not authenticated', 401)

    def load(self, token, owner):
        return copy.deepcopy(self.rows.get(owner, (0, {})))

    def save(self, token, owner, revision, value):
        if self.fail_save:
            raise RemoteError('Storage unavailable')
        if self.rows.get(owner, (0,))[0] != revision:
            raise RemoteError('Conflict', 409)
        self.rows[owner] = (revision + 1, copy.deepcopy(value))


class HostedTests(unittest.TestCase):
    def setUp(self):
        self.server = HostedServer(('127.0.0.1', 0), HostedHandler)
        self.server.public_host = 'traceweave.onrender.com'
        self.server.origin = 'https://traceweave.onrender.com'
        self.server.store = MemoryStore()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def call(self, path, data=None, user='alice', operation=None, origin=None):
        headers = {'Host': self.server.public_host}
        if user:
            headers['Cookie'] = COOKIE + '=' + user
        if data is not None:
            headers.update({'Content-Type': 'application/json',
                'Origin': origin or self.server.origin,
                'Idempotency-Key': operation or str(uuid.uuid4())})
        elif origin:
            headers['Origin'] = origin
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        connection.request('GET' if data is None else 'POST', path,
            None if data is None else json.dumps(data), headers)
        response = connection.getresponse()
        result = (response.status, json.loads(response.read()), dict(response.getheaders()))
        connection.close()
        return result

    def options(self, path, origin='https://ixotic27.github.io'):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        headers = {'Host': self.server.public_host, 'Origin': origin,
                   'Access-Control-Request-Method': 'POST',
                   'Access-Control-Request-Headers': 'Content-Type, Idempotency-Key'}
        connection.request('OPTIONS', path, None, headers)
        response = connection.getresponse()
        headers_dict = dict(response.getheaders())
        status = response.status
        connection.close()
        return status, headers_dict

    # Checks that unauthenticated users and invalid origins are denied by the hosted API.
    def test_auth_and_origin_boundaries(self):
        self.assertEqual(self.call('/api/state', user=None)[0], 401)
        self.assertFalse(self.call('/api/session', user=None)[1]['authenticated'])
        self.assertEqual(self.call('/api/ingest', {'text': 'x'}, origin='https://evil.invalid')[0], 403)
        response = self.call('/api/auth/login', {'email':'alice@example.invalid','password':'irrelevant'}, user=None)
        self.assertEqual(response[0], 200)
        self.assertIn('HttpOnly', response[2]['Set-Cookie'])
        self.assertIn('Secure', response[2]['Set-Cookie'])
        self.assertNotIn('access_token', response[1])

    # Verifies state isolation, idempotent retries, and restore-from-disk consistency for hosted data.
    def test_round_trip_isolation_and_retry(self):
        data = {'source': 'firewall', 'text': 'src=192.0.2.1 dst=198.51.100.1 action=allow\r\n'}
        operation = str(uuid.uuid4())
        self.assertEqual(self.call('/api/ingest', data, operation=operation)[0], 200)
        self.assertEqual(self.call('/api/ingest', data, operation=operation)[0], 200)
        self.assertEqual(len(self.call('/api/state')[1]['events']), 1)
        self.assertEqual(len(self.call('/api/state', user='bob')[1]['events']), 0)
        self.assertEqual(self.call('/api/ingest', {**data, 'source':'changed'}, operation=operation)[0], 409)
        # Rebuild with no in-memory engine or cache, as after a Render restart.
        stored = self.server.store.rows['alice'][1]
        engine = restore(json.loads(json.dumps(stored)))
        try:
            self.assertEqual(engine.db.execute('SELECT raw FROM events').fetchone()[0], data['text'].encode())
            self.assertEqual(engine.export(), [])
            self.assertEqual(snapshot(engine), stored)
        finally:
            engine.close()

    # Ensures a storage failure is surfaced as an error and never reports a successful write.
    def test_failed_save_does_not_report_success_or_persist(self):
        self.server.store.fail_save = True
        self.assertEqual(self.call('/api/ingest', {'text':'src=192.0.2.1 dst=198.51.100.1 action=deny'})[0], 503)
        self.assertEqual(self.call('/api/state')[1]['events'], [])

    def test_github_pages_cors_and_cross_origin_auth(self):
        # 1. CORS Preflight OPTIONS for trusted GitHub Pages origin
        status, headers = self.options('/api/events', origin='https://ixotic27.github.io')
        self.assertEqual(status, 204)
        self.assertEqual(headers.get('Access-Control-Allow-Origin'), 'https://ixotic27.github.io')
        self.assertEqual(headers.get('Access-Control-Allow-Credentials'), 'true')
        self.assertIn('POST', headers.get('Access-Control-Allow-Methods', ''))
        self.assertIn('Content-Type', headers.get('Access-Control-Allow-Headers', ''))

        # 2. CORS Preflight OPTIONS for untrusted origin is rejected
        status, headers = self.options('/api/events', origin='https://evil.invalid')
        self.assertEqual(status, 403)

        # 3. Cross-origin GET request receives CORS response headers
        status, body, headers = self.call('/api/session', user=None, origin='https://ixotic27.github.io')
        self.assertEqual(status, 200)
        self.assertFalse(body['authenticated'])
        self.assertEqual(headers.get('Access-Control-Allow-Origin'), 'https://ixotic27.github.io')
        self.assertEqual(headers.get('Access-Control-Allow-Credentials'), 'true')

        # 4. Cross-origin POST login receives SameSite=None cookie and CORS headers
        status, body, headers = self.call('/api/auth/login', {'email': 'alice@example.invalid', 'password': 'irrelevant'},
                                          user=None, origin='https://ixotic27.github.io')
        self.assertEqual(status, 200)
        self.assertEqual(headers.get('Access-Control-Allow-Origin'), 'https://ixotic27.github.io')
        self.assertEqual(headers.get('Access-Control-Allow-Credentials'), 'true')
        self.assertIn('SameSite=None', headers.get('Set-Cookie', ''))
        self.assertIn('Secure', headers.get('Set-Cookie', ''))


if __name__ == '__main__':
    unittest.main()
