import betamax
import comodo_api
import os
import pytest

customer_login_uri = os.environ.get('CUSTOMER_LOGIN_URI', 'comodo')
login = os.environ.get('LOGIN', 'comodo')
org_id = os.environ.get('ORG_ID', '1234')
password = os.environ.get('PASSWORD', 'fubar')
secret_key = os.environ.get('SECRET_KEY', 'fubar')

# A 'good' working client
@pytest.fixture(scope='class')
def api_client():
    yield comodo_api.ComodoTLSService(api_url='https://hard.cert-manager.com/private/ws/EPKIManagerSSL?wsdl',
                                      customer_login_uri=customer_login_uri, login=login, org_id=org_id,
                                      client_cert_auth=True,
                                      client_public_certificate='/etc/pki/tls/certs/comodo_client.crt',
                                      client_private_key='/etc/pki/tls/private/comodo_client.key',
                                      secret_key=secret_key, password=password)

# A 'bad' or bogus client to generate errors
@pytest.fixture(scope='class')
def bad_api_client():
    yield comodo_api.ComodoTLSService(api_url='https://hard.cert-manager.com/private/ws/EPKIManagerSSL?wsdl',
                                      customer_login_uri='BadURI', login='BadLogin', org_id=1234,
                                      client_cert_auth=False,
                                      secret_key='BadKey', password='BadPassword')

class TestComodoAPI(object):
    def test_get_cert_types(self, api_client):
        recorder = betamax.Betamax(api_client.session)
        with recorder.use_cassette('ComodoAPI_get_cert_types'):
            result = api_client.get_cert_types()

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'success' in result['status']
        assert 'data' in result
        assert 'cert_types' in result['data']
        assert isinstance(result['data']['cert_types'], list)

    def test_get_cert_types_failure(self, bad_api_client):
        recorder = betamax.Betamax(bad_api_client.session)
        with recorder.use_cassette('ComodoAPI_get_cert_types_failure'):
            result = bad_api_client.get_cert_types()

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'error' in result['status']

    def test_revoke(self, api_client):
        recorder = betamax.Betamax(api_client.session)
        with recorder.use_cassette('ComodoAPI_revoke'):
            result = api_client.revoke(cert_id=123456, reason='Revoked for testing')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'success' in result['status']

    def test_revoke_failure(self, bad_api_client):
        recorder = betamax.Betamax(bad_api_client.session)
        with recorder.use_cassette('ComodoAPI_revoke_failure'):
            result = bad_api_client.revoke(cert_id=123456, reason='Revoked for testing')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'error' in result['status']

    def test_collect(self, api_client):
        recorder = betamax.Betamax(api_client.session)
        with recorder.use_cassette('ComodoAPI_collect'):
            result = api_client.collect(cert_id=123456, format_type='X509 PEM Bundle')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'success' in result['status']
        assert 'data' in result
        assert 'certificate' in result['data']
        assert 'certificate_id' in result['data']
        assert 'certificate_status' in result['data']

    def test_collect_failure(self, bad_api_client):
        recorder = betamax.Betamax(bad_api_client.session)
        with recorder.use_cassette('ComodoAPI_collect_failure'):
            result = bad_api_client.collect(cert_id=123456, format_type='X509 PEM Bundle')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'error' in result['status']

    def test_submit(self, api_client):
        csr='''-----BEGIN CERTIFICATE REQUEST-----
        <CSR_DATA>
        -----END CERTIFICATE REQUEST-----
        '''
        recorder = betamax.Betamax(api_client.session)
        with recorder.use_cassette('ComodoAPI_submit'):
            result = api_client.submit(cert_type_name='PlatinumSSL Certificate',
                                       csr=csr, term=3, revoke_password='foo,bar',
                                       server_type='Apache/ModSSL', subject_alt_names='test2.colorado.edu')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'success' in result['status']
        assert 'data' in result
        assert 'certificate_id' in result['data']

    def test_submit_failure(self, bad_api_client):
        csr = '''-----BEGIN CERTIFICATE REQUEST-----
         <CSR_DATA>
         -----END CERTIFICATE REQUEST-----
         '''
        recorder = betamax.Betamax(bad_api_client.session)
        with recorder.use_cassette('ComodoAPI_submit_failure'):
            result = bad_api_client.submit(cert_type_name='PlatinumSSL Certificate',
                                           csr=csr, term=3, revoke_password='foo,bar',
                                           server_type='Apache/ModSSL', subject_alt_names='test2.colorado.edu')

        assert isinstance(result, dict)
        assert 'status' in result
        assert 'error' in result['status']
