import betamax
import comodo_api
import os

customer_login_uri = os.environ.get('CUSTOMER_LOGIN_URI', 'comodo')
login = os.environ.get('LOGIN', 'comodo')
org_id = os.environ.get('ORG_ID', '1234')
password = os.environ.get('PASSWORD', 'fubar')
secret_key = os.environ.get('SECRET_KEY', 'fubar')

class TestComodoAPI(object):
    def test_get_cert_types(self):
        c_api = comodo_api.ComodoTLSService(api_url='https://hard.cert-manager.com/private/ws/EPKIManagerSSL?wsdl',
                                            customer_login_uri=customer_login_uri, login=login, org_id=org_id,
                                            client_cert_auth=True,
                                            client_public_certificate='/etc/pki/tls/certs/comodo_client.crt',
                                            client_private_key='/etc/pki/tls/private/comodo_client.key',
                                            secret_key=secret_key, password=password)

        recorder = betamax.Betamax(c_api.session)
        with recorder.use_cassette('ComodoAPI_get_cert_types'):
            cert_types = c_api.get_cert_types()

        assert isinstance(cert_types, dict)

    def test_revoke(self):
        """

        :return:
        """
