import base64
import tempfile
import time
import unittest
from pathlib import Path

import jwt

from app import create_app
from database import get_db


class AuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.app = create_app({'TESTING': True, 'DATABASE': str(Path(cls.temp.name)/'test.db'),
                              'JWT_SECRET': 'test-only-secret-'*4})
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def login(self, password='Phat@123', **kwargs):
        return self.client.post('/',json={'userName':'phat', 'password':base64.b64encode(password.encode()).decode()}, **kwargs)

    def token(self):
        return self.login().json['access_token']

    def get(self, path, token):
        return self.client.get(path,headers={'Authorization':'Bearer '+token})

    def test_login_and_storage(self):
        token=self.token()
        self.assertEqual(len(token.split('.')),3)
        self.assertLessEqual(len(token),255)
        with self.app.app_context():
            user=get_db().execute('SELECT * FROM "User"').fetchone()
            self.assertEqual(user['Token'],token)
            self.assertTrue(user['Password'].startswith('scrypt:'))
            self.assertNotIn('Phat@123',user['Password'])

    def test_auth_structure(self):
        response=self.get('/auth',self.token())
        self.assertEqual(response.status_code,200)
        self.assertTrue(response.json['jwt']['signatureVerified'])
        self.assertEqual(response.json['jwt']['header']['alg'],'HS256')
        self.assertEqual(response.json['jwt']['parts'],3)

    def test_hello_requires_token(self):
        response=self.client.get('/api/hello')
        self.assertEqual(response.status_code,401)
        self.assertEqual(response.json['error'],'MISSING_TOKEN')
        self.assertNotIn('Hello World',response.get_data(as_text=True))

    def test_hello_valid(self):
        response=self.get('/api/hello',self.token())
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json['message'],'Hello World')

    def test_wrong_password(self):
        self.assertEqual(self.login('wrong').status_code,401)

    def test_unknown_user_and_sql_injection(self):
        for username in ['unknown',"' OR 1=1 --"]:
            response=self.client.post('/',json={'userName':username,'password':'UGhhdEAxMjM='})
            self.assertEqual(response.status_code,401)

    def test_invalid_input(self):
        for data in [{},[],None,{'userName':'phat','password':'%%%invalid'}, {'userName':5,'password':'abc'}, {'userName':'phat','password':'/w=='}]:
            self.assertEqual(self.client.post('/',json=data).status_code,400)

    def test_tampered_signature(self):
        token=self.token(); parts=token.split('.')
        parts[2]=('A' if parts[2][0]!='A' else 'B')+parts[2][1:]
        response=self.get('/api/hello','.'.join(parts))
        self.assertEqual(response.status_code,401)
        self.assertEqual(response.json['error'],'INVALID_TOKEN')

    def test_expired_token(self):
        token=jwt.encode({'sub':'1','iat':int(time.time())-120,'exp':int(time.time())-60,'jti':'expired'},self.app.config['JWT_SECRET'],algorithm='HS256')
        response=self.get('/auth',token)
        self.assertEqual(response.status_code,401)
        self.assertEqual(response.json['error'],'TOKEN_EXPIRED')

    def test_old_session_rejected(self):
        first=self.token(); second=self.token()
        self.assertNotEqual(first,second)
        self.assertEqual(self.get('/auth',first).json['error'],'TOKEN_REVOKED')
        self.assertEqual(self.get('/auth',second).status_code,200)

    def test_disallow_other_algorithm_and_unsigned(self):
        payload={'sub':'1','iat':int(time.time()),'exp':int(time.time())+120,'jti':'bad'}
        for algorithm,key in [('none',''),('HS384',self.app.config['JWT_SECRET'])]:
            token=jwt.encode(payload,key,algorithm=algorithm)
            self.assertEqual(self.get('/auth',token).status_code,401)

    def test_missing_required_claims(self):
        token=jwt.encode({'sub':'1'},self.app.config['JWT_SECRET'],algorithm='HS256')
        self.assertEqual(self.get('/auth',token).status_code,401)

    def test_bad_authorization_header(self):
        for value in ['Bearer', 'Basic abc','Bearer a.b.c','Bearer a b', 'Bearer '+'x'*256]:
            self.assertEqual(self.client.get('/auth',headers={'Authorization':value}).status_code,401)

    def test_docs_are_public(self):
        self.assertEqual(self.client.get('/docs').status_code,200)
        with self.client.get('/openapi.json') as response:
            self.assertEqual(response.status_code,200)


if __name__=='__main__':
    unittest.main(verbosity=2)
