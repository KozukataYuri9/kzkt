import os
import sys
import unittest


PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from app import app


class XmlImportSecurityTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()
        with self.client.session_transaction() as flask_session:
            flask_session["username"] = "admin"
            flask_session["_csrf_token"] = "test-csrf-token"

    def post_xml(self, xml_data):
        return self.client.post(
            "/xml-import",
            data={
                "csrf_token": "test-csrf-token",
                "xml_data": xml_data,
            },
        )

    def test_rejects_local_file_external_entity(self):
        payload = """<?xml version="1.0"?>
<!DOCTYPE users [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<users><user><name>&xxe;</name><email>a@example.com</email></user></users>
"""

        response = self.post_xml(payload)

        self.assertEqual(response.status_code, 400)
        self.assertIn("禁止使用 DTD、实体或外部资源声明", response.get_data(as_text=True))
        self.assertNotIn("root:x:", response.get_data(as_text=True))

    def test_rejects_remote_external_entity(self):
        payload = """<?xml version="1.0"?>
<!DOCTYPE users [<!ENTITY xxe SYSTEM "http://127.0.0.1:5001/">]>
<users><user><name>&xxe;</name><email>a@example.com</email></user></users>
"""

        response = self.post_xml(payload)

        self.assertEqual(response.status_code, 400)
        self.assertIn("禁止使用 DTD、实体或外部资源声明", response.get_data(as_text=True))

    def test_accepts_normal_user_xml(self):
        payload = """<users>
  <user><name>Alice</name><email>alice@example.com</email></user>
</users>"""

        response = self.post_xml(payload)
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Alice", body)
        self.assertIn("alice@example.com", body)


if __name__ == "__main__":
    unittest.main()
