# Copyright 2021 The Casdoor Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from unittest import IsolatedAsyncioTestCase, mock

from src.casdoor.async_main import AsyncCasdoorSDK
from src.casdoor.user import User


class TestOAuth(IsolatedAsyncioTestCase):
    """
    You should replace the code content below and
    the get_sdk() method's content with your own Casdoor
    instance and such if you need to. And running these tests successfully
    proves that your connection to Casdoor is good-and-working!
    """

    # server returned authorization code
    code = "246fb250b9c0db8d8905"

    # Casdoor user and password for auth with
    # Resource Owner Password Credentials Grant.
    # Grant type "Password" must be enabled in Casdoor Application.
    username = ""
    password = ""



    @staticmethod
    def get_sdk():

            # Casdoor certificate
        certificate = '''-----BEGIN CERTIFICATE-----
MIIE3TCCAsWgAwIBAgIDAeJAMA0GCSqGSIb3DQEBCwUAMCgxDjAMBgNVBAoTBWFk
bWluMRYwFAYDVQQDEw1jZXJ0LWJ1aWx0LWluMB4XDTIzMTEzMDA3MjIxMloXDTQz
MTEzMDA3MjIxMlowKDEOMAwGA1UEChMFYWRtaW4xFjAUBgNVBAMTDWNlcnQtYnVp
bHQtaW4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC7jkDS2iDTibUx
DSext6Z2Um2a8kBGLfllqf7few3TDWX5JTLVq1fAzmLipcUuEHIH9AjUbKFmEFSn
iqigxpgoBQYi1JY72b8pN+kjgMkmXcSAZPotxoRTz3Dv3iz5QzSjjSc0aYyeV4Gy
rFHljgIqC8ypOpqiPpnR50+R7ARSHxpWQkuuh8Fgtq59sfrwMkaBTMeuY+NxsFAR
0chM+N3Pg6yAzPaf4cP7D+B/pHq/Xq8ZJvP9Apk/INX/ByDuUss+Bw75ysImVtHR
KRHkdXSABgOMHH9z1rMc9KpD/fdrQravSa5d901uQuUIb1Cpv4cF1iJIJC1784da
Tw0qm/wIkOKv9msUNSvrXNVgUo5whyMsbrv4XyUOY2mViQU1NtZRbNC8C9Fly7p/
GH9Xv456M7ZI3BwW4i/bFiZe4qqou7wjhpamQlmrEIwjBJcMIidl8GzhlLGb4Sus
jrIelcKcqeSd/nxVPjYNoG9N6he/Xcyu3Jukr/55pTCxo16tyf7L08CDcqOVl+DK
oj9UHtGUYolm1euRzPW789CTy+vK+mlA3ZL/bp+ACSMUTxmQXR0WOwRY/hvaKg5o
8mu9rgCdDdT4m7YLhSh+LxgBbg+7tGfV1ZjVnmC/FmHDfO/kUCeJsbxb1L5hARdU
/jYAym0SnaclEBfwTvrqTDSWXlp8nQIDAQABoxAwDjAMBgNVHRMBAf8EAjAAMA0G
CSqGSIb3DQEBCwUAA4ICAQBv1t5Shsmw73p75xwlYSjv0D8CoaeppCPQAU3pruko
0AVIR+4UNB+QoLkHbGIPOgfkc1ELq23bWWsKm3Vbn5mMjn9t0eEjEvPbYWe9pxaO
eBzdut2iDgFaXzwGs1a+eQ/gYSzIBVqMP5Voa5EYjyyDDfZWpTg6wdzgci/xWb0n
qNGnc81e3sjV+4jwN2vpf+4OBSeKcaGtmFgiqxA4gK8xO/pGriYX3hVC7pyPAy4+
0HWcM6ZB5KwjT6rhPxs1EfC7cd6ktT6NeXcbdu1/0tUxkiAQ/Tc5qhXdemhTyjPm
9kEuzj3TxLlI4ntD80kE7Y8PWBaQgULroQDYUJdOOgW8goliI5oZCOSYB4phR9gn
gpuzBsv1EK6K8ok9MMCaJeF1zhleJBXFfRAumrHCo5CzV4kGAGTep0T3SgZLjLgz
x1HYe7Z4cTXFHIUVMvdanIWJWxJCWM6RAr3bhHi/Rk4Se1soCIg9PuFGSNGcQycv
fxhl82XTnLQAEuNJ8o3VZrpMFNRaKFUyjSGZVjstDg7j56k/NbhR2TCWVFvD0i7V
kj3JagdMMs9ylnK1wIvF+Jy6PgqEQA5OEDNCEbdMBEUL9ZNANGXmUgD8K98ebNjV
kDP3EJQX/5qVk0lxp/kzxHF6jwTpshJB55Xtivj7ow4V7+dmorAuRM9tPrG+LW8B
Cg==
-----END CERTIFICATE-----'''
        
        sdk = AsyncCasdoorSDK(
            endpoint='http://10.220.9.10:8000',
            client_id='f0bbff667e4643be69cb',
            client_secret='8854e76bf7e72dca269491517eeaedd032791175',
            certificate=certificate,
            org_name='GCP',
            application_name='Jarvex',
        )
        return sdk

    async def test__oauth_token_request(self):
        sdk = self.get_sdk()
        data = {
            "grant_type": sdk.grant_type,
            "client_id": sdk.client_id,
            "client_secret": sdk.client_secret,
            "code": self.code,
        }
        auth_token = await sdk._oauth_token_request(payload=data)
        self.assertIn("access_token", auth_token)

    async def test__get_payload_for_authorization_code(self):
        sdk = self.get_sdk()
        result = sdk._AsyncCasdoorSDK__get_payload_for_authorization_code(code=self.code)  # noqa: It's private method
        self.assertEqual("authorization_code", result.get("grant_type"))

    async def test__get_payload_for_password_credentials(self):
        sdk = self.get_sdk()
        result = sdk._AsyncCasdoorSDK__get_payload_for_password_credentials(  # noqa: It's private method
            username="test", password="test"
        )
        self.assertEqual("password", result.get("grant_type"))

    async def test__get_payload_for_client_credentials(self):
        sdk = self.get_sdk()
        result = sdk._AsyncCasdoorSDK__get_payload_for_client_credentials()  # noqa: It's private method
        self.assertEqual("client_credentials", result.get("grant_type"))

    async def test__get_payload_for_access_token_request_with_code(self):
        sdk = self.get_sdk()
        result = sdk._get_payload_for_access_token_request(code="test")
        self.assertEqual("authorization_code", result.get("grant_type"))

    async def test__get_payload_for_access_token_request_with_cred(self):
        sdk = self.get_sdk()
        result = sdk._get_payload_for_access_token_request(username="test", password="test")
        self.assertEqual("password", result.get("grant_type"))

    async def test_get_payload_for_access_token_request_with_client_cred(self):
        sdk = self.get_sdk()
        result = sdk._get_payload_for_access_token_request()
        self.assertEqual("client_credentials", result.get("grant_type"))

    async def test_get_oauth_token_with_password(self):
        sdk = self.get_sdk()
        token = await sdk.get_oauth_token(username=self.username, password=self.password)
        access_token = token.get("access_token")
        self.assertIsInstance(access_token, str)

    async def test_get_oauth_token_with_client_cred(self):
        sdk = self.get_sdk()
        token = await sdk.get_oauth_token()
        print(json.dumps(token, indent=4))
        access_token = token.get("access_token")
        self.assertIsInstance(access_token, str)

    async def test_get_oauth_token(self):
        sdk = self.get_sdk()
        token = await sdk.get_oauth_token(code=self.code)
        access_token = token.get("access_token")
        self.assertIsInstance(access_token, str)

    async def test_oauth_token_request(self):
        sdk = self.get_sdk()
        response = await sdk.oauth_token_request(self.code)
        self.assertIsInstance(response, dict)

    async def test_refresh_token_request(self):
        sdk = self.get_sdk()
        response = await sdk.oauth_token_request(self.code)
        print(json.dumps(response, indent=4))
        refresh_token = response.get("refresh_token")
        self.assertIsInstance(refresh_token, str)
        response = await sdk.refresh_token_request(refresh_token)
        print('===refresh ===')
        print(json.dumps(response, indent=4))
        self.assertIsInstance(response, dict)

    async def test_get_oauth_refreshed_token(self):

        sdk = self.get_sdk()
        # response = await sdk.oauth_token_request(self.code)
        # refresh_token = response.get("refresh_token")
        refresh_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJvd25lciI6IkdDUCIsIm5hbWUiOiJkb25nd2VpIiwiY3JlYXRlZFRpbWUiOiIyMDI0LTA1LTI4VDE1OjEwOjAxKzA4OjAwIiwidXBkYXRlZFRpbWUiOiIyMDI0LTA1LTI4VDA3OjExOjE0WiIsImlkIjoiODc0MjQ4ZWQtOTJkOS00NDMzLWI5YzAtODU3ZjQzYzBmZmIxIiwidHlwZSI6Im5vcm1hbC11c2VyIiwicGFzc3dvcmQiOiIiLCJwYXNzd29yZFNhbHQiOiIiLCJwYXNzd29yZFR5cGUiOiJwbGFpbiIsImRpc3BsYXlOYW1lIjoiZG9uZ3dlaSIsImZpcnN0TmFtZSI6IiIsImxhc3ROYW1lIjoiIiwiYXZhdGFyIjoiIiwiYXZhdGFyVHlwZSI6IiIsInBlcm1hbmVudEF2YXRhciI6IiIsImVtYWlsIjoiZG9uZ3dlaUB6ZXR5dW4uY29tIiwiZW1haWxWZXJpZmllZCI6ZmFsc2UsInBob25lIjoiMTg2MTUyNjEzNzkiLCJjb3VudHJ5Q29kZSI6IkNOIiwicmVnaW9uIjoiQ04iLCJsb2NhdGlvbiI6IiIsImFkZHJlc3MiOltdLCJhZmZpbGlhdGlvbiI6IkV4YW1wbGUgSW5jLiIsInRpdGxlIjoiIiwiaWRDYXJkVHlwZSI6IiIsImlkQ2FyZCI6IiIsImhvbWVwYWdlIjoiIiwiYmlvIjoiIiwibGFuZ3VhZ2UiOiIiLCJnZW5kZXIiOiIiLCJiaXJ0aGRheSI6IiIsImVkdWNhdGlvbiI6IiIsInNjb3JlIjoyMDAwLCJrYXJtYSI6MCwicmFua2luZyI6MywiaXNEZWZhdWx0QXZhdGFyIjpmYWxzZSwiaXNPbmxpbmUiOmZhbHNlLCJpc0FkbWluIjpmYWxzZSwiaXNGb3JiaWRkZW4iOmZhbHNlLCJpc0RlbGV0ZWQiOmZhbHNlLCJzaWdudXBBcHBsaWNhdGlvbiI6IkphcnZleCIsImhhc2giOiIiLCJwcmVIYXNoIjoiIiwiYWNjZXNzS2V5IjoiIiwiYWNjZXNzU2VjcmV0IjoiIiwiZ2l0aHViIjoiIiwiZ29vZ2xlIjoiIiwicXEiOiIiLCJ3ZWNoYXQiOiIiLCJmYWNlYm9vayI6IiIsImRpbmd0YWxrIjoiIiwid2VpYm8iOiIiLCJnaXRlZSI6IiIsImxpbmtlZGluIjoiIiwid2Vjb20iOiIiLCJsYXJrIjoiIiwiZ2l0bGFiIjoiIiwiY3JlYXRlZElwIjoiIiwibGFzdFNpZ25pblRpbWUiOiIiLCJsYXN0U2lnbmluSXAiOiIiLCJwcmVmZXJyZWRNZmFUeXBlIjoiIiwicmVjb3ZlcnlDb2RlcyI6bnVsbCwidG90cFNlY3JldCI6IiIsIm1mYVBob25lRW5hYmxlZCI6ZmFsc2UsIm1mYUVtYWlsRW5hYmxlZCI6ZmFsc2UsImxkYXAiOiIiLCJwcm9wZXJ0aWVzIjp7fSwicm9sZXMiOltdLCJwZXJtaXNzaW9ucyI6W10sImdyb3VwcyI6W10sImxhc3RTaWduaW5Xcm9uZ1RpbWUiOiIiLCJzaWduaW5Xcm9uZ1RpbWVzIjowLCJ0b2tlblR5cGUiOiJyZWZyZXNoLXRva2VuIiwidGFnIjoic3RhZmYiLCJpc3MiOiJodHRwOi8vMTAuMjIwLjkuMTA6ODAwMCIsInN1YiI6Ijg3NDI0OGVkLTkyZDktNDQzMy1iOWMwLTg1N2Y0M2MwZmZiMSIsImF1ZCI6WyJmMGJiZmY2NjdlNDY0M2JlNjljYiJdLCJleHAiOjE3MTg4ODA5MDIsIm5iZiI6MTcxODI3NjEwMiwiaWF0IjoxNzE4Mjc2MTAyLCJqdGkiOiJhZG1pbi8wYTVkOGNkNC1mNzBmLTQ0YzQtOGJkMy0xMGQ2NTI4N2EzZjIifQ.ZlA1_1L32_qTkkNKZw4zXQC77MBmqmrOWWZF1bkwhnHXQA3M-zvcPTuEy_UC-H74_yhM-CmFfofJrcZOw8cp1tByQ8lbQCtxkbHw7owHcmx0-fb-J2jpIDfWRTGF1JogO9aPtVqqvnJFYhV3tCadoVFE3bp153F3eDn_knRLseFcmcHs3IMqjQ_UjX9RbBya5PN-AULYpQ5n_yotJMBDF4lQdSsp274lFhUCIz0rAXxHFgNjtdp9yVJcihTs_MhheaYpu8teSsvZyAjlXY0tTfXQ64B32hYARD6N-nhBc_y4c1iTot4Jc3CaXJWcBgpfGKPCmqIkWbTsnNnNzZ9dWIlwkP4Aor-pXfi6E2jYJGJrwvgLIXbpI9IFDirA-aZvAa1-W5_uUy7dxQk3Sajj-G_cN1MqX61dVHPigLklxbQRDyAcb_60eO7fTToKDgWKjT2QyN7eqzKaO7o3TqzHPbX4x5Xszuh4Uud7UkYtNiRe6LHmmil0nmFW8PcuJ6xqscRbuk_pluPqBMGBasfU8sdcjpDzf-OLwlo262gTDVvZ0mN_qXpo-_4ElsHbMKILQojoRxGhPNeuRwN3ebNhBPyPyWpid49MDkr4i02eiouI0DA_kRHNnz5hDjQeXh4j8AhmyqrBFyQG2JcwV6zNhQPKaocihi0qIzohWBD98G8"
        response = await sdk.refresh_oauth_token(refresh_token)
        print(f"access_token:{response}")
        self.assertIsInstance(response, str)

    async def test_parse_jwt_token(self):
        sdk = self.get_sdk()
        # token = await sdk.get_oauth_token(code=self.code)
        # access_token = token.get("access_token")
        access_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkdDUC1jZXJ0IiwidHlwIjoiSldUIn0.eyJvd25lciI6IkdDUCIsIm5hbWUiOiJkb25nd2VpIiwiY3JlYXRlZFRpbWUiOiIyMDI0LTA1LTI4VDE1OjEwOjAxKzA4OjAwIiwidXBkYXRlZFRpbWUiOiIyMDI0LTA1LTI4VDA3OjExOjE0WiIsImlkIjoiODc0MjQ4ZWQtOTJkOS00NDMzLWI5YzAtODU3ZjQzYzBmZmIxIiwidHlwZSI6Im5vcm1hbC11c2VyIiwicGFzc3dvcmQiOiIiLCJwYXNzd29yZFNhbHQiOiIiLCJwYXNzd29yZFR5cGUiOiJwbGFpbiIsImRpc3BsYXlOYW1lIjoiZG9uZ3dlaSIsImZpcnN0TmFtZSI6IiIsImxhc3ROYW1lIjoiIiwiYXZhdGFyIjoiIiwiYXZhdGFyVHlwZSI6IiIsInBlcm1hbmVudEF2YXRhciI6IiIsImVtYWlsIjoiZG9uZ3dlaUB6ZXR5dW4uY29tIiwiZW1haWxWZXJpZmllZCI6ZmFsc2UsInBob25lIjoiMTg2MTUyNjEzNzkiLCJjb3VudHJ5Q29kZSI6IkNOIiwicmVnaW9uIjoiQ04iLCJsb2NhdGlvbiI6IiIsImFkZHJlc3MiOltdLCJhZmZpbGlhdGlvbiI6IkV4YW1wbGUgSW5jLiIsInRpdGxlIjoiIiwiaWRDYXJkVHlwZSI6IiIsImlkQ2FyZCI6IiIsImhvbWVwYWdlIjoiIiwiYmlvIjoiIiwibGFuZ3VhZ2UiOiIiLCJnZW5kZXIiOiIiLCJiaXJ0aGRheSI6IiIsImVkdWNhdGlvbiI6IiIsInNjb3JlIjoyMDAwLCJrYXJtYSI6MCwicmFua2luZyI6MywiaXNEZWZhdWx0QXZhdGFyIjpmYWxzZSwiaXNPbmxpbmUiOmZhbHNlLCJpc0FkbWluIjpmYWxzZSwiaXNGb3JiaWRkZW4iOmZhbHNlLCJpc0RlbGV0ZWQiOmZhbHNlLCJzaWdudXBBcHBsaWNhdGlvbiI6IkphcnZleCIsImhhc2giOiIiLCJwcmVIYXNoIjoiIiwiYWNjZXNzS2V5IjoiIiwiYWNjZXNzU2VjcmV0IjoiIiwiZ2l0aHViIjoiIiwiZ29vZ2xlIjoiIiwicXEiOiIiLCJ3ZWNoYXQiOiIiLCJmYWNlYm9vayI6IiIsImRpbmd0YWxrIjoiIiwid2VpYm8iOiIiLCJnaXRlZSI6IiIsImxpbmtlZGluIjoiIiwid2Vjb20iOiIiLCJsYXJrIjoiIiwiZ2l0bGFiIjoiIiwiY3JlYXRlZElwIjoiIiwibGFzdFNpZ25pblRpbWUiOiIiLCJsYXN0U2lnbmluSXAiOiIiLCJwcmVmZXJyZWRNZmFUeXBlIjoiIiwicmVjb3ZlcnlDb2RlcyI6bnVsbCwidG90cFNlY3JldCI6IiIsIm1mYVBob25lRW5hYmxlZCI6ZmFsc2UsIm1mYUVtYWlsRW5hYmxlZCI6ZmFsc2UsImxkYXAiOiIiLCJwcm9wZXJ0aWVzIjp7fSwicm9sZXMiOltdLCJwZXJtaXNzaW9ucyI6W10sImdyb3VwcyI6W10sImxhc3RTaWduaW5Xcm9uZ1RpbWUiOiIiLCJzaWduaW5Xcm9uZ1RpbWVzIjowLCJ0b2tlblR5cGUiOiJhY2Nlc3MtdG9rZW4iLCJ0YWciOiJzdGFmZiIsImlzcyI6Imh0dHA6Ly8xMC4yMjAuOS4xMDo4MDAwIiwic3ViIjoiODc0MjQ4ZWQtOTJkOS00NDMzLWI5YzAtODU3ZjQzYzBmZmIxIiwiYXVkIjpbImYwYmJmZjY2N2U0NjQzYmU2OWNiIl0sImV4cCI6MTcxODg4MDkwMiwibmJmIjoxNzE4Mjc2MTAyLCJpYXQiOjE3MTgyNzYxMDIsImp0aSI6ImFkbWluLzBhNWQ4Y2Q0LWY3MGYtNDRjNC04YmQzLTEwZDY1Mjg3YTNmMiJ9.cVxqs303RcIy3t-329mxo_WiLsfra6JViTlBDGttmYiiRtKpuTjibKXyNJTC_N3d_vs6p7YdkUWvNJ2lzyi3-5pKDNMa5NhDST2wQkeos4Y_wlyrkWAtlw9lxK81SWERmAETH-O2u8Xt1WTALTQKEkcAQf8RwU_Ta6643Id_JCx1vICi9c61owh8B4O1u2EcyIdKrW_liQYubdQkB6MZMJkCKifFploRC78MzPKqw-cwn-tYsMon7xlMXrAwr1vTr6u0UcHBVDXkZ5i8qp4P4KW0cI9j97k3SzjmrMsasIfz56fPc_CGwijqmkqW_PqPWCaJUGi0OL0qfNzPc8neduwE6fT-UT5mFccZj4e18aynhOAHaT8QRoxjgRREIAiB5xSjvqsktPFq9npPpWA54ld524YWmAve2tkpnNwlx2BkJulVmOpTDkjMlZAEiQb6tkzkLBe5_BSolaaKsX89wHu0SOwZR49_DWyitI4loZkE9bzdGeZwvyzMcn8MwrTEhBkr5Vbe74qZHVzXE6vsZAGFjsVG3OSLkl0397RbXtbWVj8CjQ4Vcfs3wS26aTc74WLzvp-Pznrn-R645o-GGt1etM3K80AGGHcr1AM30mJ8uYbT3Q0HSF2Wy0adNjEGR_33gle7OXuxoGQWm-p1d9GfhARQZYXPFFkyzmYvWqQ"
        decoded_msg = sdk.parse_jwt_token(access_token)
        print(json.dumps(decoded_msg, indent=4))
        self.assertIsInstance(decoded_msg, dict)

    async def test_enforce(self):
        sdk = self.get_sdk()
        status = await sdk.enforce("built-in/permission-built-in", "admin", "a", "ac")
        self.assertIsInstance(status, bool)

    def mocked_enforce_requests_post(*args, **kwargs):
        class MockResponse:
            def __init__(
                self,
                json_data,
                status_code=200,
            ):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        result = True
        for i in range(0, 5):
            if kwargs.get("json").get(f"v{i}") != f"v{i}":
                result = False

        return MockResponse(result)

    @mock.patch("aiohttp.ClientSession.post", side_effect=mocked_enforce_requests_post)
    async def test_enforce_parmas(self, mock_post):
        sdk = self.get_sdk()
        status = await sdk.enforce(
            "built-in/permission-built-in",
            "v0",
            "v1",
            "v2",
            v3="v3",
            v4="v4",
            v5="v5",
        )
        self.assertEqual(status, True)

    def mocked_batch_enforce_requests_post(*args, **kwargs):
        class MockResponse:
            def __init__(
                self,
                json_data,
                status_code=200,
            ):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

        json = kwargs.get("json")
        result = [True for i in range(0, len(json))]
        for k in range(0, len(json)):
            for i in range(0, len(json[k]) - 1):
                if json[k].get(f"v{i}") != f"v{i}":
                    result[k] = False

        return MockResponse(result)

    @mock.patch(
        "aiohttp.ClientSession.post",
        side_effect=mocked_batch_enforce_requests_post,
    )
    def test_batch_enforce(self, mock_post):
        sdk = self.get_sdk()
        status = sdk.batch_enforce(
            "built-in/permission-built-in",
            [
                ["v0", "v1", "v2", "v3", "v4", "v5"],
                ["v0", "v1", "v2", "v3", "v4", "v1"],
            ],
        )
        self.assertEqual(len(status), 2)
        self.assertEqual(status[0], True)
        self.assertEqual(status[1], False)

    @mock.patch(
        "aiohttp.ClientSession.post",
        side_effect=mocked_batch_enforce_requests_post,
    )
    def test_batch_enforce_raise(self, mock_post):
        sdk = self.get_sdk()
        with self.assertRaises(ValueError) as context:
            sdk.batch_enforce("built-in/permission-built-in", [["v0", "v1"]])
        self.assertEqual("Invalid permission rule[0]: ['v0', 'v1']", str(context.exception))

    async def test_get_users(self):
        sdk = self.get_sdk()
        users = await sdk.get_users()
        self.assertIsInstance(users, list)

    async def test_get_user(self):
        sdk = self.get_sdk()
        user = await sdk.get_user("admin")
        self.assertIsInstance(user, dict)
        self.assertEqual(user["name"], "admin")

    async def test_get_user_count(self):
        sdk = self.get_sdk()
        online_count = await sdk.get_user_count(is_online=True)
        offline_count = await sdk.get_user_count(is_online=False)
        all_count = await sdk.get_user_count()
        self.assertIsInstance(online_count, int)
        self.assertIsInstance(offline_count, int)
        self.assertIsInstance(all_count, int)
        self.assertEqual(online_count + offline_count, all_count)

    async def test_modify_user(self):
        sdk = self.get_sdk()
        user = User()
        user.name = "test_ffyuanda"
        user.owner = sdk.org_name
        await sdk.delete_user(user)

        response = await sdk.add_user(user)
        self.assertEqual(response["data"], "Affected")

        response = await sdk.delete_user(user)
        self.assertEqual(response["data"], "Affected")

        response = await sdk.add_user(user)
        self.assertEqual(response["data"], "Affected")

        user.phone = "phone"
        response = await sdk.update_user(user)
        self.assertEqual(response["data"], "Affected")

        self.assertIn("status", response)
        self.assertIsInstance(response, dict)

    def check_enforce_request(*args, **kwargs):
        return True

    async def test_auth_link(self):
        sdk = self.get_sdk()
        redirect_uri = "http://localhost:9000/callback"
        response = await sdk.get_auth_link(redirect_uri=redirect_uri)  # pure compose redirect url str with endpoint
        print(response)
        self.assertEqual(
            response,
            f"{sdk.front_endpoint}/login/oauth/authorize?client_id={sdk.client_id}&response_type=code&redirect_uri={redirect_uri}&scope=read&state={sdk.application_name}",  # noqa
        )
