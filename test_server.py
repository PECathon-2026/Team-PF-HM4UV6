import base64
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from PIL import ImageDraw, ImageFont

import server


def tesseract_available():
    configured = os.environ.get("TESSERACT_CMD", "")
    if configured and Path(configured).is_file():
        return True
    if shutil.which("tesseract"):
        return True
    if os.name == "nt":
        executable = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Tesseract-OCR" / "tesseract.exe"
        return executable.is_file()
    return False


@unittest.skipIf(server.Image is None or server.pytesseract is None, "Install requirements.txt to test local OCR.")
class LocalOcrTests(unittest.TestCase):
    def test_missing_ocr_engine_fails_closed(self):
        image_buffer = io.BytesIO()
        server.Image.new("RGB", (4, 4), "white").save(image_buffer, format="PNG")

        with patch.object(
            server.pytesseract,
            "image_to_string",
            side_effect=server.pytesseract.TesseractNotFoundError(),
        ):
            with self.assertRaisesRegex(RuntimeError, "image was not sent"):
                server.extract_image_text(image_buffer.getvalue())

    @unittest.skipUnless(tesseract_available(), "Install the local Tesseract OCR engine.")
    def test_real_local_ocr_detects_and_censors_sensitive_text(self):
        image = server.Image.new("RGB", (1100, 180), "white")
        font = ImageFont.load_default(size=48)
        ImageDraw.Draw(image).text(
            (20, 45),
            "Password: DemoPass123!",
            fill="black",
            font=font,
        )
        image_buffer = io.BytesIO()
        image.save(image_buffer, format="PNG")

        text, mime = server.extract_image_text(image_buffer.getvalue())
        result = server.scan_text(text)

        self.assertEqual(mime, "image/png")
        self.assertIn("DemoPass", text)
        safe_content = server.censor_text(text, result["preview_segments"])
        self.assertEqual(safe_content, "Password: [REDACTED]\n")
        self.assertNotIn("DemoPass1", safe_content)
        self.assertNotIn("23!", safe_content)


class PrivacyScannerTests(unittest.TestCase):
    def test_detects_international_and_indian_phone_formats_in_sentences(self):
        text = (
            "Call me on +91 98765-43210 or +1 (415) 555-2671. "
            "UK office: +44 20 7946 0958; AU: +61.412.345.678. "
            "India local: 98765 43210. Order number 2025 is unrelated."
        )
        result = server.scan_text(text)
        detected = [
            segment["text"]
            for segment in result["preview_segments"]
            if segment["kind"] == "finding" and segment["finding"]["category"] == "Phone number"
        ]
        censored = server.censor_text(text, result["preview_segments"])

        self.assertEqual(len(detected), 5)
        self.assertNotIn("+91 98765-43210", censored)
        self.assertNotIn("+1 (415) 555-2671", censored)
        self.assertNotIn("+44 20 7946 0958", censored)
        self.assertNotIn("+61.412.345.678", censored)
        self.assertNotIn("98765 43210", censored)
        self.assertIn("Order number 2025 is unrelated.", censored)

    def test_detects_cards_with_different_separators_and_ignores_invalid_numbers(self):
        text = (
            "Card 4111111111111111 was charged; another is 4111-1111-1111-1111. "
            "This is not a valid card: 4111.1111.1111.1112. Order 1234567890123456."
        )
        result = server.scan_text(text)
        detected = [
            segment["text"]
            for segment in result["preview_segments"]
            if segment["kind"] == "finding" and segment["finding"]["category"] == "Payment card"
        ]
        censored = server.censor_text(text, result["preview_segments"])

        self.assertEqual(detected, ["4111111111111111", "4111-1111-1111-1111"])
        self.assertIn("4111.1111.1111.1112", censored)
        self.assertIn("Order 1234567890123456.", censored)

    def test_detects_aadhaar_and_pan_in_normal_text(self):
        aadhaar_prefix = "23456789012"
        aadhaar = next(
            aadhaar_prefix + str(check_digit)
            for check_digit in range(10)
            if server._passes_verhoeff(aadhaar_prefix + str(check_digit))
        )
        formatted_aadhaar = f"{aadhaar[:4]} {aadhaar[4:8]} {aadhaar[8:]}"
        text = (
            f"My Aadhaar is {formatted_aadhaar}, and PAN ABCPE1234F is on file. "
            "Invoice 2026 is not an identifier."
        )
        result = server.scan_text(text)
        categories = [finding["category"] for finding in result["findings"]]
        censored = server.censor_text(text, result["preview_segments"])

        self.assertIn("Aadhaar number", categories)
        self.assertIn("PAN number", categories)
        self.assertNotIn(formatted_aadhaar, censored)
        self.assertNotIn("ABCPE1234F", censored)
        self.assertIn("Invoice 2026 is not an identifier.", censored)

    def test_unlabeled_aadhaar_requires_a_valid_verhoeff_checksum(self):
        prefix = "34567890123"
        valid_aadhaar = next(
            prefix + str(check_digit)
            for check_digit in range(10)
            if server._passes_verhoeff(prefix + str(check_digit))
        )
        invalid_aadhaar = valid_aadhaar[:-1] + str((int(valid_aadhaar[-1]) + 1) % 10)
        text = f"Identifier {valid_aadhaar} and unrelated number {invalid_aadhaar}."

        result = server.scan_text(text)
        detected_values = [
            segment["text"]
            for segment in result["preview_segments"]
            if segment["kind"] == "finding"
        ]

        self.assertEqual(detected_values, [valid_aadhaar])
        self.assertIn(invalid_aadhaar, server.censor_text(text, result["preview_segments"]))

    def test_detects_bank_details_codes_and_identifiers(self):
        text = (
            "Pay account number 123456789012. IFSC HDFC0001234 and SWIFT HDFCINBB. "
            "IBAN GB82 WEST 1234 5698 7654 32. UPI id alice@okaxis."
        )
        result = server.scan_text(text)
        categories = {finding["category"] for finding in result["findings"]}
        censored = server.censor_text(text, result["preview_segments"])

        self.assertIn("Bank account details", categories)
        self.assertIn("Banking code", categories)
        self.assertIn("Banking identifier", categories)
        for value in ("123456789012", "HDFC0001234", "HDFCINBB", "GB82 WEST 1234 5698 7654 32", "alice@okaxis"):
            self.assertNotIn(value, censored)
        self.assertIn("Pay account number [REDACTED]", censored)

    def test_scans_and_censors_multiple_sensitive_categories(self):
        text = (
            "Customer: Alice Example\n"
            "Email: alice@example.test\n"
            "Password: DemoPass123!\n"
            "Card: 4111 1111 1111 1111\n"
            "Bank account: 123456789012"
        )

        result = server.scan_text(text)
        categories = {finding["category"] for finding in result["findings"]}
        censored = server.censor_text(text, result["preview_segments"])

        self.assertTrue({
            "Personal name",
            "Email address",
            "Authentication secret",
            "Payment card",
            "Bank account details",
        }.issubset(categories))
        for value in ("Alice Example", "alice@example.test", "DemoPass123!", "4111 1111 1111 1111", "123456789012"):
            self.assertNotIn(value, censored)
        self.assertIn("[REDACTED]", censored)
        self.assertIn("Customer: [REDACTED]\nEmail: [REDACTED]", censored)

    def test_sensitive_wording_without_a_value_is_still_flagged(self):
        result = server.scan_text("Do not display my password or bank details.")
        categories = {finding["category"] for finding in result["findings"]}

        self.assertIn("Authentication secret", categories)
        self.assertIn("Bank account details", categories)

    def test_selected_field_type_flags_unlabelled_identifiers(self):
        result = server.scan_text("STU-2026-4481", "student id")

        self.assertEqual(result["findings"][0]["category"], "Personal identifier")
        self.assertEqual(server.censor_text("STU-2026-4481", result["preview_segments"]), "[REDACTED]")

    def test_card_detection_uses_luhn_check(self):
        result = server.scan_text("Card: 4111 1111 1111 1111\nCard: 4111 1111 1111 1112")
        card_matches = [
            segment["text"]
            for segment in result["preview_segments"]
            if segment["kind"] == "finding" and segment["finding"]["category"] == "Payment card"
        ]

        self.assertEqual(card_matches, ["4111 1111 1111 1111"])

    def test_detects_labeled_card_types_and_non_luhn_numbers(self):
        text = (
            "ATM card number: 1234 5678 9012\n"
            "Gift card code: 12345678\n"
            "Store card details: 4111-1111-1111-1111\n"
            "Visa card number: 123456789012"
        )
        result = server.scan_text(text)
        detected = [
            segment["text"]
            for segment in result["preview_segments"]
            if segment["kind"] == "finding" and segment["finding"]["category"] == "Payment card"
        ]
        censored = server.censor_text(text, result["preview_segments"])

        self.assertEqual(detected, ["1234 5678 9012", "12345678", "4111-1111-1111-1111", "123456789012"])
        self.assertNotIn("1234 5678 9012", censored)
        self.assertNotIn("12345678", censored)
        self.assertNotIn("4111-1111-1111-1111", censored)
        self.assertNotIn("123456789012", censored)

    def test_flags_common_card_types_even_without_a_number(self):
        result = server.scan_text("Keep my prepaid card and loyalty card private.")
        categories = [finding["category"] for finding in result["findings"]]

        self.assertEqual(categories.count("Payment card"), 2)

    def test_scanner_allows_file_origin_but_not_secure_send(self):
        handler = object.__new__(server.PrivacyLensHandler)
        handler.headers = Message()
        handler.headers["Origin"] = "null"

        handler.path = "/api/scan"
        self.assertTrue(handler._origin_is_allowed())

        handler.path = "/api/secure-send"
        self.assertFalse(handler._origin_is_allowed())

        handler.path = "/api/scan-image"
        self.assertTrue(handler._origin_is_allowed())

        handler.path = "/api/local-seal"
        self.assertTrue(handler._origin_is_allowed())

        handler.path = "/api/secure-send"
        self.assertFalse(handler._origin_is_allowed())

    def test_scanner_allows_common_local_dev_server_ports(self):
        handler = object.__new__(server.PrivacyLensHandler)
        handler.headers = Message()
        handler.headers["Origin"] = "http://localhost:5173"
        handler.headers["Host"] = "127.0.0.1:8000"
        handler.path = "/api/scan"

        self.assertTrue(handler._origin_is_allowed())

    def test_scanner_rejects_non_local_origins(self):
        handler = object.__new__(server.PrivacyLensHandler)
        handler.headers = Message()
        handler.headers["Origin"] = "https://privacy.example"
        handler.headers["Host"] = "127.0.0.1:8000"
        handler.path = "/api/scan"

        self.assertFalse(handler._origin_is_allowed())


@unittest.skipIf(server.AESGCM is None, "Install requirements.txt to test AES-GCM.")
class SecureTransmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.vault_file = Path(self.temporary_directory.name) / "vault.sqlite3"
        self.environment = patch.dict(os.environ, {
            "PRIVACY_VAULT_PATH": str(self.vault_file),
            "PRIVACY_ENCRYPTION_KEY": base64.b64encode(bytes(range(32))).decode("ascii"),
        })
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary_directory.cleanup()

    def create_record(self, text):
        result = server.scan_text(text)
        safe_content = server.censor_text(text, result["preview_segments"])
        categories = sorted({finding["category"] for finding in result["findings"]})
        return server.store_protected_record(
            text.encode("utf-8"),
            safe_content,
            categories,
            "text",
            "text/plain; charset=utf-8",
        )

    def test_aes_gcm_round_trip(self):
        key = bytes(range(32))
        plaintext = "Password: DemoPass123!"
        envelope = server.encrypt_message(plaintext, key)
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        tag = base64.b64decode(envelope["tag"])

        self.assertEqual(envelope["algorithm"], "AES-256-GCM")
        self.assertEqual(server.AESGCM(key).decrypt(nonce, ciphertext + tag, server.AAD).decode(), plaintext)
        self.assertNotIn(plaintext, json.dumps(envelope))

    def test_scan_persists_only_encrypted_original_and_returns_redacted_preview(self):
        text = "Password: DemoPass123!"
        handler = object.__new__(server.PrivacyLensHandler)
        response = {}
        payload = json.dumps({"text": text}).encode("utf-8")
        handler.path = "/api/scan"
        handler.headers = Message()
        handler.headers["Content-Type"] = "application/json"
        handler.headers["Content-Length"] = str(len(payload))
        handler.rfile = io.BytesIO(payload)
        handler._origin_is_allowed = lambda: True
        handler._send_json = lambda status, value: response.update(status=status, value=value)

        handler.do_POST()

        result = response["value"]
        record = server.get_protected_record(result["record_id"])
        database = sqlite3.connect(self.vault_file)
        stored_ciphertext = database.execute(
            "SELECT original_ciphertext FROM protected_records WHERE record_id = ?",
            (result["record_id"],),
        ).fetchone()[0]
        database.close()
        self.assertEqual(response["status"], 200)
        self.assertNotIn("DemoPass123!", json.dumps(result))
        self.assertNotIn("DemoPass123!", stored_ciphertext.decode("latin1"))
        self.assertEqual(server.decrypt_record(record), text.encode("utf-8"))
        self.assertEqual(result["safe_content"], "Password: [REDACTED]")
        self.assertTrue(result["encrypted_storage"])

    def test_image_ocr_route_returns_local_text_and_encrypts_original_image(self):
        image_bytes = b"fictional image bytes"
        text = "Password: DemoPass123!"
        payload = json.dumps({"image": base64.b64encode(image_bytes).decode("ascii")}).encode("utf-8")
        handler = object.__new__(server.PrivacyLensHandler)
        response = {}
        handler.path = "/api/scan-image"
        handler.headers = Message()
        handler.headers["Content-Type"] = "application/json"
        handler.headers["Content-Length"] = str(len(payload))
        handler.rfile = io.BytesIO(payload)
        handler._origin_is_allowed = lambda: True
        handler._send_json = lambda status, value: response.update(status=status, value=value)

        with patch("server.extract_image_text", return_value=(text, "image/png")):
            handler.do_POST()

        result = response["value"]
        record = server.get_protected_record(result["record_id"])
        self.assertEqual(response["status"], 200)
        self.assertEqual(result["extracted_text"], text)
        self.assertEqual(result["safe_content"], "Password: [REDACTED]")
        self.assertEqual(record["source_kind"], "image")
        self.assertEqual(server.decrypt_record(record), image_bytes)

    @unittest.skipUnless(tesseract_available(), "Install the local Tesseract OCR engine.")
    def test_real_image_route_returns_ocr_text_and_stages_ciphertext(self):
        image = server.Image.new("RGB", (1100, 180), "white")
        ImageDraw.Draw(image).text(
            (20, 45),
            "Password: DemoPass123!",
            fill="black",
            font=ImageFont.load_default(size=48),
        )
        image_buffer = io.BytesIO()
        image.save(image_buffer, format="PNG")
        image_bytes = image_buffer.getvalue()
        payload = json.dumps({
            "image": base64.b64encode(image_bytes).decode("ascii"),
        }).encode("utf-8")
        handler = object.__new__(server.PrivacyLensHandler)
        response = {}
        handler.path = "/api/scan-image"
        handler.headers = Message()
        handler.headers["Content-Type"] = "application/json"
        handler.headers["Content-Length"] = str(len(payload))
        handler.rfile = io.BytesIO(payload)
        handler._origin_is_allowed = lambda: True
        handler._send_json = lambda status, value: response.update(status=status, value=value)

        handler.do_POST()

        result = response["value"]
        record = server.get_protected_record(result["record_id"])
        self.assertEqual(response["status"], 200)
        self.assertEqual(result["source_kind"], "image")
        self.assertIn("DemoPass", result["extracted_text"])
        self.assertEqual(result["safe_content"], "Password: [REDACTED]\n")
        self.assertEqual(server.decrypt_record(record), image_bytes)

    def test_recipient_endpoint_requires_authorization_before_decryption(self):
        text = "Password: AuthorizedOnly123!"
        record_id = self.create_record(text)
        handler = object.__new__(server.PrivacyLensHandler)
        response = {}
        handler.path = f"/api/records/{record_id}/original"
        handler.headers = Message()
        handler.headers["Authorization"] = "Bearer wrong"
        handler._origin_is_allowed = lambda: True
        handler._send_json = lambda status, value: response.update(status=status, value=value)

        handler.do_GET()

        self.assertEqual(response["status"], 401)
        self.assertNotIn("AuthorizedOnly123!", json.dumps(response))

    def test_authorized_recipient_can_decrypt_original(self):
        text = "Password: AuthorizedOnly123!"
        record_id = self.create_record(text)
        handler = object.__new__(server.PrivacyLensHandler)
        response = {}
        handler.path = f"/api/records/{record_id}/original"
        handler.headers = Message()
        handler.headers["Authorization"] = "Bearer " + ("r" * 40)
        handler._origin_is_allowed = lambda: True
        handler._send_json = lambda status, value: response.update(status=status, value=value)

        with patch.dict(os.environ, {"PRIVACY_RECIPIENT_TOKEN": "r" * 40}):
            handler.do_GET()

        self.assertEqual(response["status"], 200)
        self.assertEqual(response["value"]["original_text"], text)

    def test_encryption_key_is_persisted_outside_the_frontend(self):
        key_file = Path(self.temporary_directory.name) / "generated.key"
        with patch.dict(os.environ, {
            "PRIVACY_ENCRYPTION_KEY": "",
            "PRIVACY_ENCRYPTION_KEY_FILE": str(key_file),
        }):
            first_key = server.encryption_key_from_environment()
            second_key = server.encryption_key_from_environment()

        self.assertEqual(len(first_key), 32)
        self.assertEqual(first_key, second_key)
        self.assertEqual(key_file.read_bytes(), first_key)

    def test_secure_send_forwards_only_cleaned_content(self):
        record_id = self.create_record("Password: DemoPass123!")
        response = type("Response", (), {"status": 202, "__enter__": lambda self: self, "__exit__": lambda *args: None})()
        requests = []

        class FakeOpener:
            def open(self, request, timeout):
                requests.append(request)
                return response

        with patch.dict(os.environ, {
            "DESTINATION_URL": "https://receiver.example/inbox",
            "DESTINATION_BEARER_TOKEN": "destination-secret-token",
        }):
            with patch("server.urllib.request.build_opener", return_value=FakeOpener()):
                result = server.secure_send(record_id)

        sent_body = json.loads(requests[0].data)
        self.assertTrue(result["success"])
        self.assertTrue(result["encrypted_storage"])
        self.assertEqual(result["mode"], "redacted")
        self.assertNotIn("DemoPass123!", json.dumps(sent_body))
        self.assertEqual(sent_body["content"], "Password: [REDACTED]")
        self.assertNotIn("payload", sent_body)
        self.assertEqual(
            requests[0].get_header("Authorization"),
            "Bearer destination-secret-token",
        )

    def test_local_encryption_verifies_ciphertext_without_network_or_plaintext(self):
        text = "Password: DemoPass123!"
        record_id = self.create_record(text)
        with patch("server.urllib.request.build_opener") as build_opener:
            result = server.verify_local_encryption(record_id)

        build_opener.assert_not_called()
        self.assertTrue(result["success"])
        self.assertEqual(result["mode"], "local-encrypted")
        self.assertTrue(result["encrypted_storage"])
        self.assertEqual(result["finding_count"], 1)
        self.assertNotIn(text, json.dumps(result))

    def test_local_seal_endpoint_returns_verified_local_status(self):
        record_id = self.create_record("Password: DemoPass123!")
        payload = json.dumps({"record_id": record_id}).encode("utf-8")
        handler = object.__new__(server.PrivacyLensHandler)
        response = {}
        handler.path = "/api/local-seal"
        handler.headers = Message()
        handler.headers["Content-Type"] = "application/json"
        handler.headers["Content-Length"] = str(len(payload))
        handler.rfile = io.BytesIO(payload)
        handler._origin_is_allowed = lambda: True
        handler._send_json = lambda status, value: response.update(status=status, value=value)

        with patch("server.urllib.request.build_opener") as build_opener:
            handler.do_POST()

        build_opener.assert_not_called()
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["value"]["mode"], "local-encrypted")
        self.assertNotIn("DemoPass123!", json.dumps(response["value"]))

    def test_local_encryption_rejects_corrupted_ciphertext(self):
        record_id = self.create_record("Password: DemoPass123!")
        database = sqlite3.connect(self.vault_file)
        try:
            ciphertext = database.execute(
                "SELECT original_ciphertext FROM protected_records WHERE record_id = ?",
                (record_id,),
            ).fetchone()[0]
            database.execute(
                "UPDATE protected_records SET original_ciphertext = ? WHERE record_id = ?",
                (bytes([ciphertext[0] ^ 1]) + ciphertext[1:], record_id),
            )
            database.commit()
        finally:
            database.close()

        with self.assertRaisesRegex(RuntimeError, "Encrypted staging could not be verified"):
            server.verify_local_encryption(record_id)

    def test_secure_send_rebuilds_redaction_from_verified_encrypted_original(self):
        record_id = self.create_record("Password: DemoPass123!")
        database = sqlite3.connect(self.vault_file)
        try:
            database.execute(
                "UPDATE protected_records SET safe_content = ? WHERE record_id = ?",
                ("Password: DemoPass123!", record_id),
            )
            database.commit()
        finally:
            database.close()
        response = type("Response", (), {"status": 202, "__enter__": lambda self: self, "__exit__": lambda *args: None})()
        requests = []

        class FakeOpener:
            def open(self, request, timeout):
                requests.append(request)
                return response

        with patch.dict(os.environ, {"DESTINATION_URL": "https://receiver.example/inbox"}):
            with patch("server.urllib.request.build_opener", return_value=FakeOpener()):
                server.secure_send(record_id)

        sent_body = json.loads(requests[0].data)
        self.assertEqual(sent_body["content"], "Password: [REDACTED]")
        self.assertNotIn("DemoPass123!", json.dumps(sent_body))

    def test_corrupted_encrypted_staging_blocks_transmission(self):
        record_id = self.create_record("Password: DemoPass123!")
        database = sqlite3.connect(self.vault_file)
        try:
            ciphertext = database.execute(
                "SELECT original_ciphertext FROM protected_records WHERE record_id = ?",
                (record_id,),
            ).fetchone()[0]
            database.execute(
                "UPDATE protected_records SET original_ciphertext = ? WHERE record_id = ?",
                (bytes([ciphertext[0] ^ 1]) + ciphertext[1:], record_id),
            )
            database.commit()
        finally:
            database.close()

        with patch.dict(os.environ, {"DESTINATION_URL": "https://receiver.example/inbox"}):
            with patch("server.urllib.request.build_opener") as build_opener:
                with self.assertRaisesRegex(RuntimeError, "Encrypted staging could not be verified"):
                    server.secure_send(record_id)
        build_opener.assert_not_called()

    def test_secure_send_never_forwards_encrypted_image_or_image_bytes(self):
        image_bytes = b"private image bytes"
        record_id = server.store_protected_record(
            image_bytes,
            "Email: [REDACTED]",
            ["Email address"],
            "image",
            "image/png",
        )
        response = type("Response", (), {"status": 202, "__enter__": lambda self: self, "__exit__": lambda *args: None})()
        requests = []

        class FakeOpener:
            def open(self, request, timeout):
                requests.append(request)
                return response

        with patch.dict(os.environ, {"DESTINATION_URL": "https://receiver.example/inbox"}):
            with patch("server.urllib.request.build_opener", return_value=FakeOpener()):
                with patch("server.extract_image_text", return_value=("Email: demo@example.test", "image/png")):
                    server.secure_send(record_id)

        sent_body = json.loads(requests[0].data)
        self.assertEqual(sent_body["content"], "Email: [REDACTED]")
        self.assertNotIn("image", json.dumps(sent_body).lower())
        self.assertNotIn(base64.b64encode(image_bytes).decode("ascii"), json.dumps(sent_body))

    def test_missing_destination_blocks_transmission(self):
        record_id = self.create_record("Password: DemoPass123!")
        with patch.dict(os.environ, {"DESTINATION_URL": ""}):
            with patch("server.urllib.request.build_opener") as build_opener:
                with self.assertRaisesRegex(RuntimeError, "HTTPS destination"):
                    server.secure_send(record_id)
        build_opener.assert_not_called()

    def test_unmatched_text_is_still_sent_only_after_encrypted_staging(self):
        record_id = self.create_record("This message contains no configured pattern.")
        response = type("Response", (), {"status": 202, "__enter__": lambda self: self, "__exit__": lambda *args: None})()
        requests = []

        class FakeOpener:
            def open(self, request, timeout):
                requests.append(request)
                return response

        with patch.dict(os.environ, {"DESTINATION_URL": "https://receiver.example/inbox"}):
            with patch("server.urllib.request.build_opener", return_value=FakeOpener()):
                result = server.secure_send(record_id)

        self.assertTrue(result["success"])
        self.assertEqual(json.loads(requests[0].data)["content"], "This message contains no configured pattern.")

    def test_missing_encryption_key_blocks_transmission(self):
        with patch.dict(os.environ, {"PRIVACY_ENCRYPTION_KEY": "invalid"}):
            with self.assertRaisesRegex(RuntimeError, "Encryption configuration is invalid"):
                self.create_record("Password: DemoPass123!")


if __name__ == "__main__":
    unittest.main()
