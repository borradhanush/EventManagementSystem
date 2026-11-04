"""Phase 16 page, role-navigation and static camera selection checks."""

import tempfile
import unittest
from pathlib import Path

import app as webapp
import database


class FaceCameraUiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DATABASE_PATH = Path(self.temp_dir.name) / "phase16.db"
        database.init_db()
        webapp.app.config.update(TESTING=True, SECRET_KEY="phase16-tests")
        self.client = webapp.app.test_client()
        with database.get_db() as db:
            self.user_id = db.execute(
                "INSERT INTO users(full_name,email,password_hash,affiliation,role) VALUES('Camera User','camera@p16.test','hash','internal','user')"
            ).lastrowid
            self.root_id = db.execute(
                "INSERT INTO users(full_name,email,password_hash,affiliation,role) VALUES('Root User','root@p16.test','hash','internal','root')"
            ).lastrowid

    def tearDown(self):
        self.temp_dir.cleanup()

    def login(self, user_id, role="user"):
        with self.client.session_transaction() as session:
            session["user_id"] = user_id
            session["role"] = role

    def test_face_registration_and_verification_pages_load(self):
        self.login(self.user_id)
        registration = self.client.get("/face-registration")
        verification = self.client.get("/face-verification")
        self.assertEqual(registration.status_code, 200)
        self.assertEqual(verification.status_code, 200)
        self.assertIn(b"Capture with camera", registration.data)
        self.assertIn(b"Capture with camera", verification.data)

    def test_upload_based_face_flow_remains_available(self):
        self.login(self.user_id)
        for route, button in (("/face-registration", b"Generate embedding and register"),
                              ("/face-verification", b"Verify face")):
            page = self.client.get(route).data
            self.assertIn(b'enctype="multipart/form-data"', page)
            self.assertIn(b'type="file" name="image" accept="image/jpeg,image/png"', page)
            self.assertIn(button, page)

    def test_face_pages_require_login(self):
        for route in ("/face-registration", "/face-verification"):
            response = self.client.get(route)
            self.assertEqual(response.status_code, 302)
            self.assertIn(b"/login", response.data)

    def test_camera_selection_uses_standard_apis_and_selected_device(self):
        self.login(self.user_id)
        page = self.client.get("/face-registration").data
        source = (Path(webapp.app.static_folder) / "js" / "camera_selection.js").read_text(encoding="utf-8")
        self.assertIn(b'id="camera-select"', page)
        self.assertIn(b'id="camera"', page)
        self.assertIn("navigator.mediaDevices.enumerateDevices()", source)
        self.assertIn("navigator.mediaDevices.getUserMedia", source)
        self.assertIn("deviceId: { exact: requestedId }", source)

    def test_camera_stream_is_stopped_on_switch_disconnect_and_page_exit(self):
        source = (Path(webapp.app.static_folder) / "js" / "camera_selection.js").read_text(encoding="utf-8")
        self.assertIn("activeStream.getTracks().forEach(track => track.stop())", source)
        self.assertIn("selector.addEventListener('change'", source)
        self.assertIn("addEventListener('ended'", source)
        self.assertIn("window.addEventListener('pagehide', stopStream", source)
        self.assertIn("window.addEventListener('beforeunload', stopStream", source)

    def test_friendly_camera_errors_and_verification_result_rendering_exist(self):
        source = (Path(webapp.app.static_folder) / "js" / "camera_selection.js").read_text(encoding="utf-8")
        for expected in ("permission was denied", "No camera is available", "selected camera is unavailable",
                         "does not support camera selection", "replaceChildren(section)", "image instead"):
            self.assertIn(expected.lower(), source.lower())

    def test_role_navigation_keeps_root_out_of_participant_private_area(self):
        self.login(self.root_id, "root")
        root_page = self.client.get("/dashboard")
        self.assertEqual(root_page.status_code, 200)
        self.assertIn(b"Root review", root_page.data)
        self.assertNotIn(b"Face registration", root_page.data)
        self.assertNotIn(b"My registrations", root_page.data)
        self.login(self.user_id)
        participant_page = self.client.get("/dashboard")
        self.assertIn(b"My registrations", participant_page.data)
        self.assertNotIn(b"Root review", participant_page.data)


if __name__ == "__main__":
    unittest.main()
