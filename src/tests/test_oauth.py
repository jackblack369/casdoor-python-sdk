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

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from unittest import TestCase, mock

from requests import Response

from src.casdoor.main import CasdoorSDK
from src.casdoor.user import User
import pytest



class TestOAuth(TestCase):
    """
    You should replace the code content below and
    the get_sdk() method's content with your own Casdoor
    instance and such if you need to. And running these tests successfully
    proves that your connection to Casdoor is good-and-working!
    """

    # server returned authorization code
    code = "6d038ac60d4e1f17e742"

    # Casdoor user and password for auth with
    # Resource Owner Password Credentials Grant.
    # Grant type "Password" must be enabled in Casdoor Application.
    username = "dongwei"
    password = "123456"

    @staticmethod
    def get_sdk():

    # Casdoor certificate
        certificate = '''-----BEGIN CERTIFICATE-----
MIIE2TCCAsGgAwIBAgIDAeJAMA0GCSqGSIb3DQEBCwUAMCYxDjAMBgNVBAoTBWFk
bWluMRQwEgYDVQQDDAtjZXJ0XzVrazFhZTAeFw0yNDA1MjcxMDQ1NDdaFw00NDA1
MjcxMDQ1NDdaMCYxDjAMBgNVBAoTBWFkbWluMRQwEgYDVQQDDAtjZXJ0XzVrazFh
ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMOLQ/iMxT8HZqFW+g1/
aUOIe4Tw0gQnrCyhMAH0HSb65mR7nZANLhChXYK5J1S0I+4ek79wFdF/HqG8c2jv
/hl1+BafDjFq17k0ZMxENpL/uQLg0COz4bE0KaR6VuTiC1NPQmHeq9lknXi1J+Ac
Hv6vMklZSU+YmmF+oc8F5CKunBUYslr6nfcA5C61FtZc4XzQnfPsVeSbX5JBnMXW
Tyyd9PokymkpUoawgR0sHc3QcAGyGdgItBkY7llAWvsatnkcNFXe3xOkhdeSuODf
CFYDhW1qySbEIOvKpHMHty80Xhg+41iY0zqHygm4X0rx+VNqE8DXRatjEiZuiIO/
6s++PB9L1ORrbUl4RPgqxcr8RQ8GREdDv2z4pge85wogx1JBg6hgP62kvWnfWi+I
ir/yFtnNnxkTz2o9EJ4MgZ0RmgWuzN/KTHYFHmR1nbtVWqU4EhwQu2jAA6QfrNsk
RArpjeRDQEeedR+gMrHG3W0TLwNRe5298S+UoxWhcQT+iB6MScDYvBaDNCdU32gV
7wBdsVX+2IMCZtaIET8Xk6ShCFa082Jv23ffwQ5g7v5yfqkMbeCn88hqeTzjSsx3
eqWF3QI6uKtozElFOdrg1YXxN8bJH5MxdbS9ErQGkyNXJ1sQPLEjtChlDdISTAyt
45oh/IkSIG7p6M2mPzGI0zU1AgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZI
hvcNAQELBQADggIBAJQC9eo3fbpvIDzaFONpBYk+SVfGG0mB1foVwNbm40vd1b/F
p7ioP1Jvj3q/UX89TGl+y/v7FYE6LKEBflrE7uRQsDTKXExfdxOZBRyEUOEpicLM
zzML9Udu0DooA9kgsloQyTfTknClu9GHnnkGmjhCJCEg/DczWN93W2itUTGu0mcG
XQBJ5oPb/VCfWCFIFVt4wATzEpcH9XMl9gKY4sd2dnVYfZgz4hXSJTBaMXq4LHzj
N3OYxvf14ktB9xYEQzIUt2m+uoFvMFdVG2EkB4MzKjsIV9zqVATmEts7NpSZTnyk
QP0oXX+/qbyGUKbgPvQINfiAn732ODc5Gk1GTLzH4XIX6DnVKv/ad+UAxHtX/cN5
fO+NBXKS/IvmK6YRh6lKMYHjDX2KQwhYKgMBCN7zaknxyB/Alq0f1tYvSlAr/9rA
7Yw+mKPnI1OZrXHHZbD6XYL2LQzUDN0+5+GpggzNElnnoWP2BRdIyfNy/ZYL/rXj
hxgNNW4QYIGyyUXm03DRF2TVPAIt8Bj1l28ys2pniSGkqVUgMswg8VrTESNwbHCG
Af244esqv5Oh9zUSZ9AbU2kgCsNTu9Ih/WnRBdStxi3EZMfyG417S6cqqSrbtmDd
F4QnHR0rJdbUIWCXYtIQbcm5P7xrmlW9U3NGJG1kvyzR6BY95Jr44BFL/G80
-----END CERTIFICATE-----'''

        #sdk = CasdoorSDK(
        #    endpoint="https://demo.casdoor.com",
        #    client_id="3267f876b11e7d1cb217",
        #    client_secret="3f0d1f06d28d65309c8f38b505cb9dcfa487754d",
        #    certificate="CasdoorSecret",
        #    org_name="built-in",
        #    application_name="app-built-in",
        #)
        sdk = CasdoorSDK(
            endpoint='http://172.20.31.12:18000',
            client_id='66913c06cc414d1865c7',
            client_secret='f0a67b016544895c8f0e3db1b3bfc0a6bc3396d6',
            certificate=certificate,
            org_name='datacanvas',
            application_name='python-ci-1',
        )
        return sdk

    def test__oauth_token_request(self):
        sdk = self.get_sdk()
        data = {
            "grant_type": sdk.grant_type,
            "client_id": sdk.client_id,
            "client_secret": sdk.client_secret,
            "code": self.code,
        }
        response = sdk._oauth_token_request(payload=data)
        self.assertIsInstance(response, dict)

    def test__get_payload_for_authorization_code(self):
        sdk = self.get_sdk()
        result = sdk._CasdoorSDK__get_payload_for_authorization_code(code=self.code)  # noqa: It's private method
        self.assertEqual("authorization_code", result.get("grant_type"))

    def test__get_payload_for_client_credentials(self):
        sdk = self.get_sdk()
        result = sdk._CasdoorSDK__get_payload_for_client_credentials()  # noqa: It's private method
        self.assertEqual("client_credentials", result.get("grant_type"))

    def test__get_payload_for_password_credentials(self):
        sdk = self.get_sdk()
        result = sdk._CasdoorSDK__get_payload_for_password_credentials(  # noqa: It's private method
            username="test", password="test"
        )
        self.assertEqual("password", result.get("grant_type"))

    def test__get_payload_for_access_token_request_with_code(self):
        sdk = self.get_sdk()
        result = sdk._get_payload_for_access_token_request(code="test")
        self.assertEqual("authorization_code", result.get("grant_type"))

    def test__get_payload_for_access_token_request_with_client_cred(self):
        sdk = self.get_sdk()
        result = sdk._get_payload_for_access_token_request()
        self.assertEqual("client_credentials", result.get("grant_type"))

    def test__get_payload_for_access_token_request_with_cred(self):
        sdk = self.get_sdk()
        result = sdk._get_payload_for_access_token_request(username="test", password="test")
        self.assertEqual("password", result.get("grant_type"))

    #@pytest.mark
    def test_get_oauth_token_with_client_cred(self):
        sdk = self.get_sdk()
        token = sdk.get_oauth_token()
        access_token = token.get("access_token")
        print(f"access_token:[{access_token}]")
        decoded_msg = sdk.parse_jwt_token(access_token)
        print(f"decoded_msg:[{decoded_msg}]")
        '''
        {
            "owner": "admin",
            "name": "python-ci-1",
            "createdTime": "",
            "updatedTime": "",
            "deletedTime": "",
            "id": "admin/python-ci-1",
            "type": "application",
            "password": "",
            "passwordSalt": "",
            "passwordType": "",
            "displayName": "",
            "firstName": "",
            "lastName": "",
            "avatar": "",
            "avatarType": "",
            "permanentAvatar": "",
            "email": "",
            "emailVerified": false,
            "phone": "",
            "countryCode": "",
            "region": "",
            "location": "",
            "address": [],
            "affiliation": "",
            "title": "",
            "idCardType": "",
            "idCard": "",
            "homepage": "",
            "bio": "",
            "language": "",
            "gender": "",
            "birthday": "",
            "education": "",
            "score": 0,
            "karma": 0,
            "ranking": 0,
            "isDefaultAvatar": false,
            "isOnline": false,
            "isAdmin": false,
            "isForbidden": false,
            "isDeleted": false,
            "signupApplication": "",
            "hash": "",
            "preHash": "",
            "accessKey": "",
            "accessSecret": "",
            "github": "",
            "google": "",
            "qq": "",
            "wechat": "",
            "facebook": "",
            "dingtalk": "",
            "weibo": "",
            "gitee": "",
            "linkedin": "",
            "wecom": "",
            "lark": "",
            "gitlab": "",
            "createdIp": "",
            "lastSigninTime": "",
            "lastSigninIp": "",
            "preferredMfaType": "",
            "recoveryCodes": "None",
            "totpSecret": "",
            "mfaPhoneEnabled": false,
            "mfaEmailEnabled": false,
            "ldap": "",
            "properties": {},
            "roles": [],
            "permissions": [],
            "groups": [],
            "lastSigninWrongTime": "",
            "signinWrongTimes": 0,
            "tokenType": "access-token",
            "tag": "",
            "iss": "http://172.20.31.12:18000",
            "sub": "admin/python-ci-1",
            "aud": [
                "66913c06cc414d1865c7"
            ],
            "exp": 1717419645,
            "nbf": 1716814845,
            "iat": 1716814845,
            "jti": "admin/8030c2a4-1208-4dc6-9ba2-679653791e79"
            }
        '''
        self.assertIsInstance(access_token, str)

    def test_get_oauth_token_with_code(self):
        sdk = self.get_sdk()
        token = sdk.get_oauth_token(code=self.code)
        access_token = token.get("access_token")
        self.assertIsInstance(access_token, str)

    def test_get_oauth_token_with_password(self):
        sdk = self.get_sdk()
        token = sdk.get_oauth_token(username=self.username, password=self.password)
        access_token = token.get("access_token")
        print(f"access_token:[{access_token}]")
        decoded_msg = sdk.parse_jwt_token(access_token)
        print(f"decoded_msg:[{decoded_msg}]")
        '''
        {
            "owner": "datacanvas",
            "name": "dongwei",
            "createdTime": "2024-05-27T21:02:28+08:00",
            "updatedTime": "2024-05-27T13:04:09Z",
            "deletedTime": "",
            "id": "5b3e7c6e-6024-427e-8450-505e04cf5fe7",
            "type": "normal-user",
            "password": "",
            "passwordSalt": "",
            "passwordType": "salt",
            "displayName": "董威",
            "firstName": "",
            "lastName": "",
            "avatar": "https://cdn.casbin.org/img/casbin.svg",
            "avatarType": "",
            "permanentAvatar": "",
            "email": "dongwei@gmail.com",
            "emailVerified": false,
            "phone": "14513513328",
            "countryCode": "US",
            "region": "",
            "location": "",
            "address": [],
            "affiliation": "Example Inc.",
            "title": "",
            "idCardType": "",
            "idCard": "",
            "homepage": "",
            "bio": "",
            "language": "",
            "gender": "",
            "birthday": "",
            "education": "",
            "score": 2000,
            "karma": 0,
            "ranking": 2,
            "isDefaultAvatar": false,
            "isOnline": false,
            "isAdmin": true,
            "isForbidden": false,
            "isDeleted": false,
            "signupApplication": "python-ci-1",
            "hash": "",
            "preHash": "",
            "accessKey": "",
            "accessSecret": "",
            "github": "",
            "google": "",
            "qq": "",
            "wechat": "",
            "facebook": "",
            "dingtalk": "",
            "weibo": "",
            "gitee": "",
            "linkedin": "",
            "wecom": "",
            "lark": "",
            "gitlab": "",
            "createdIp": "",
            "lastSigninTime": "",
            "lastSigninIp": "",
            "preferredMfaType": "",
            "recoveryCodes": "None",
            "totpSecret": "",
            "mfaPhoneEnabled": false,
            "mfaEmailEnabled": false,
            "ldap": "",
            "properties": {},
            "roles": [],
            "permissions": [],
            "groups": [],
            "lastSigninWrongTime": "",
            "signinWrongTimes": 0,
            "tokenType": "access-token",
            "tag": "staff",
            "iss": "http://172.20.31.12:18000",
            "sub": "5b3e7c6e-6024-427e-8450-505e04cf5fe7",
            "aud": [
                "66913c06cc414d1865c7"
            ],
            "exp": 1717420040,
            "nbf": 1716815240,
            "iat": 1716815240,
            "jti": "admin/ea8c3d1b-8403-43ea-ab4a-08395f39f0ab"
        }
        '''
        self.assertIsInstance(access_token, str)

    def test_oauth_token_request(self):
        sdk = self.get_sdk()
        response = sdk.oauth_token_request(self.code)
        self.assertIsInstance(response, Response)

    def test_refresh_token_request(self):
        sdk = self.get_sdk()
        response = sdk.oauth_token_request(self.code)
        refresh_token = response.json().get("refresh_token")
        response = sdk.refresh_token_request(refresh_token)
        self.assertIsInstance(response, Response)

    def test_get_oauth_refreshed_token(self):
        sdk = self.get_sdk()
        response = sdk.oauth_token_request(self.code)
        refresh_token = response.json().get("refresh_token")
        response = sdk.refresh_oauth_token(refresh_token)
        self.assertIsInstance(response, str)

    def test_parse_jwt_token(self):
        sdk = self.get_sdk()
        token = sdk.get_oauth_token(self.code)
        access_token = token.get("access_token")
        decoded_msg = sdk.parse_jwt_token(access_token)
        self.assertIsInstance(decoded_msg, dict)

    def test_enforce(self):
        sdk = self.get_sdk()
        status = sdk.enforce("built-in/permission-built-in", "admin", "a", "ac")
        self.assertIsInstance(status, bool)

    def mocked_enforce_requests_post(*args, **kwargs):
        class MockResponse:
            def __init__(self, json_data, status_code=200, headers=None):
                if headers is None:
                    headers = {"content-type": "json"}
                    self.json_data = json_data
                    self.status_code = status_code
                    self.headers = headers

            def json(self):
                return self.json_data

        result = True
        for i in range(0, 5):
            if kwargs.get("json").get(f"v{i}") != f"v{i}":
                result = False

        return MockResponse(result)

    @mock.patch("requests.post", side_effect=mocked_enforce_requests_post)
    def test_enforce_parmas(self, mock_post):
        sdk = self.get_sdk()
        status = sdk.enforce("built-in/permission-built-in", "v0", "v1", "v2", v3="v3", v4="v4", v5="v5")
        self.assertEqual(status, True)

    def mocked_batch_enforce_requests_post(*args, **kwargs):
        class MockResponse:
            def __init__(self, json_data, status_code=200, headers=None):
                if headers is None:
                    headers = {"content-type": "json"}
                    self.json_data = json_data
                    self.status_code = status_code
                    self.headers = headers

            def json(self):
                return self.json_data

        json = kwargs.get("json")
        result = [True for i in range(0, len(json))]
        for k in range(0, len(json)):
            for i in range(0, len(json[k]) - 1):
                if json[k].get(f"v{i}") != f"v{i}":
                    result[k] = False

        return MockResponse(result)

    @mock.patch("requests.post", side_effect=mocked_batch_enforce_requests_post)
    def test_batch_enforce(self, mock_post):
        sdk = self.get_sdk()
        status = sdk.batch_enforce(
            "built-in/permission-built-in", [["v0", "v1", "v2", "v3", "v4", "v5"], ["v0", "v1", "v2", "v3", "v4", "v1"]]
        )
        self.assertEqual(len(status), 2)
        self.assertEqual(status[0], True)
        self.assertEqual(status[1], False)

    @mock.patch("requests.post", side_effect=mocked_batch_enforce_requests_post)
    def test_batch_enforce_raise(self, mock_post):
        sdk = self.get_sdk()
        with self.assertRaises(ValueError) as context:
            sdk.batch_enforce("built-in/permission-built-in", [["v0", "v1"]])
        self.assertEqual("Invalid permission rule[0]: ['v0', 'v1']", str(context.exception))

    def test_get_users(self):
        sdk = self.get_sdk()
        users = sdk.get_users()
        self.assertIsInstance(users, list)

    def test_get_user_count(self):
        sdk = self.get_sdk()
        online_count = sdk.get_user_count(is_online=True)
        offline_count = sdk.get_user_count(is_online=False)
        all_count = sdk.get_user_count()
        self.assertIsInstance(online_count, int)
        self.assertIsInstance(offline_count, int)
        self.assertIsInstance(all_count, int)
        self.assertEqual(online_count + offline_count, all_count)

    def test_get_user(self):
        sdk = self.get_sdk()
        user = sdk.get_user("admin")
        self.assertIsInstance(user, dict)

    def test_modify_user(self):
        sdk = self.get_sdk()
        user = User()
        user.name = "test_ffyuanda"
        sdk.delete_user(user)

        response = sdk.add_user(user)
        self.assertEqual(response["data"], "Affected")

        response = sdk.delete_user(user)
        self.assertEqual(response["data"], "Affected")

        response = sdk.add_user(user)
        self.assertEqual(response["data"], "Affected")

        user.phone = "phone"
        response = sdk.update_user(user)
        self.assertEqual(response["data"], "Affected")

        self.assertIn("status", response)
        self.assertIsInstance(response, dict)
