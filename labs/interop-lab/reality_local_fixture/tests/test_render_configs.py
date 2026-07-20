import json
import pathlib
import sys
import unittest


FIXTURE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FIXTURE))

from render_configs import b64url_to_hex, render  # noqa: E402


class RenderConfigsTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((FIXTURE / "manifest.json").read_text())
        self.rendered = render(self.manifest)

    def test_reverse_client_targets_rust_server_with_vision(self):
        config = self.rendered["go_reverse_client.json"]
        inbound = config["inbounds"][0]
        outbound = config["outbounds"][0]

        self.assertEqual(
            inbound["listen_port"], self.manifest["ports"]["go_reverse_client_socks"]
        )
        self.assertEqual(
            outbound["server_port"], self.manifest["ports"]["rust_reality_server"]
        )
        self.assertEqual(outbound["flow"], self.manifest["flow"])
        self.assertEqual(
            outbound["tls"]["reality"]["public_key"],
            self.manifest["x25519"]["public_key_b64"],
        )

    def test_private_key_derivation_is_same_x25519_key(self):
        self.assertEqual(
            len(b64url_to_hex(self.manifest["x25519"]["private_key_b64"])), 64
        )

    def test_rust_server_is_production_app_shape(self):
        config = self.rendered["rust_server.json"]
        inbound = config["inbounds"][0]
        reality = inbound["tls"]["reality"]
        self.assertEqual(inbound["type"], "vless")
        self.assertEqual(inbound["port"], self.manifest["ports"]["rust_reality_server"])
        self.assertEqual(inbound["users"][0]["uuid"], self.manifest["uuid"])
        self.assertEqual(reality["private_key"], self.manifest["x25519"]["private_key_b64"])
        self.assertEqual(reality["handshake"]["server_port"], self.manifest["ports"]["tls_dest"])


if __name__ == "__main__":
    unittest.main()
