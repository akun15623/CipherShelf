import os
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("VAULT_ROOT", tempfile.gettempdir())

from fastapi.testclient import TestClient

import app


HEADERS = {"X-SVault-Request": "1"}
PASSWORD = "Integration-Password-123!"


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        app.VAULT_ROOT = os.path.realpath(self.root)
        app.PRESET_PASSWORD = None
        app.VAULT_UNCONFIGURED = False
        app._status_cache.update({"at": 0.0, "initialized": False})
        with app._sessions_lock:
            app._sessions.clear()
        with app._tasks_lock:
            app._tasks.clear()
        with app._login_lock:
            app._login_failures.clear()
        self.client = TestClient(app.app)

    def tearDown(self):
        self.client.close()
        self.tmp.cleanup()

    def unlock(self, client=None):
        client = client or self.client
        response = client.post(
            "/api/unlock",
            headers=HEADERS,
            json={"password": PASSWORD, "password_confirmation": PASSWORD},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def wait_task(self, task_id, client=None):
        client = client or self.client
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            response = client.get(f"/api/progress/{task_id}")
            self.assertEqual(response.status_code, 200, response.text)
            data = response.json()
            if data["status"] != "running":
                return data
            time.sleep(0.02)
        self.fail("task timeout")

    def test_end_to_end_web_roundtrip(self):
        folder = os.path.join(self.root, "docs")
        os.makedirs(folder)
        with open(os.path.join(folder, "hello.txt"), "wb") as stream:
            stream.write(b"hello")
        self.unlock()
        response = self.client.post("/api/encrypt", headers=HEADERS, json={"paths": ["docs"]})
        self.assertEqual(response.status_code, 200, response.text)
        result = self.wait_task(response.json()["task_id"])
        self.assertEqual(result["status"], "done", result)
        response = self.client.post("/api/lock", headers=HEADERS)
        self.assertEqual(response.status_code, 200, response.text)
        response = self.client.post(
            "/api/unlock", headers=HEADERS, json={"password": PASSWORD},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["initialized"])
        response = self.client.post("/api/decrypt", headers=HEADERS, json={"paths": ["docs"]})
        self.assertEqual(response.status_code, 200, response.text)
        result = self.wait_task(response.json()["task_id"])
        self.assertEqual(result["status"], "done", result)
        with open(os.path.join(folder, "hello.txt"), "rb") as stream:
            self.assertEqual(stream.read(), b"hello")

    def test_csrf_root_and_output_escape_are_rejected(self):
        os.makedirs(os.path.join(self.root, "vault"))
        self.unlock()
        response = self.client.post("/api/encrypt", json={"paths": ["vault"]})
        self.assertEqual(response.status_code, 403)
        response = self.client.post("/api/encrypt", headers=HEADERS, json={"paths": [""]})
        self.assertEqual(response.status_code, 400)
        for output in ("../escape", "/tmp/escape", "vault/../escape"):
            response = self.client.post(
                "/api/decrypt", headers=HEADERS,
                json={"paths": ["vault"], "output": output},
            )
            self.assertIn(response.status_code, (400, 403), response.text)

    def test_reverse_proxy_gateway_origin_is_accepted(self):
        # 飞牛统一网关反代场景：Origin 是网关域、Host 被改写为内网地址，
        # 但网关登录态校验通过后注入 X-Trim-Userid，POST 不应被 CSRF 拒绝。
        os.makedirs(os.path.join(self.root, "docs"))
        with open(os.path.join(self.root, "docs", "a.txt"), "wb") as stream:
            stream.write(b"x")
        proxy_headers = {
            "X-SVault-Request": "1",
            "Origin": "https://192.168.10.4:5667",
            "Host": "127.0.0.1:8090",
            "X-Trim-Userid": "1000",
        }
        response = self.client.post(
            "/api/unlock", headers=proxy_headers,
            json={"password": PASSWORD, "password_confirmation": PASSWORD},
        )
        self.assertEqual(response.status_code, 200, response.text)
        token = response.json()["token"]
        auth = {**proxy_headers, "Authorization": f"Bearer {token}"}
        response = self.client.post("/api/encrypt", headers=auth, json={"paths": ["docs"]})
        self.assertEqual(response.status_code, 200, response.text)
        result = self.wait_task(response.json()["task_id"])
        self.assertEqual(result["status"], "done", result)

    def test_bearer_session_is_invalidated_by_lock_without_cookie(self):
        response = self.unlock()
        token = response.json()["token"]
        self.client.cookies.clear()
        bearer = {"Authorization": f"Bearer {token}"}

        self.assertEqual(self.client.get("/api/tree?path=", headers=bearer).status_code, 200)
        response = self.client.post("/api/lock", headers={**HEADERS, **bearer})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.client.get("/api/tree?path=", headers=bearer).status_code, 401)
        with app._sessions_lock:
            self.assertNotIn(token, app._sessions)

    def test_only_task_owner_can_read_and_mutations_are_serialized(self):
        for name in ("one", "two"):
            os.makedirs(os.path.join(self.root, name))
            with open(os.path.join(self.root, name, "file"), "wb") as stream:
                stream.write(b"data")
        other = TestClient(app.app)
        try:
            self.unlock(self.client)
            self.unlock(other)
            started = threading.Event()
            release = threading.Event()
            original = app.crypto.encrypt_folder

            def slow_encrypt(*args, **kwargs):
                started.set()
                release.wait(5)
                return original(*args, **kwargs)

            with patch("app.crypto.encrypt_folder", side_effect=slow_encrypt):
                response = self.client.post("/api/encrypt", headers=HEADERS, json={"paths": ["one"]})
                self.assertEqual(response.status_code, 200, response.text)
                task_id = response.json()["task_id"]
                self.assertTrue(started.wait(2))
                self.assertEqual(other.get(f"/api/progress/{task_id}").status_code, 404)
                busy = other.post("/api/encrypt", headers=HEADERS, json={"paths": ["two"]})
                self.assertEqual(busy.status_code, 409, busy.text)
                release.set()
                self.assertEqual(self.wait_task(task_id)["status"], "done")
        finally:
            other.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
