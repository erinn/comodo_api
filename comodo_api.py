from requests import Session
import sys
from zeep import Client
from zeep.transports import Transport


class ComodoCA(object):
    """
    Top level class for the Comodo CA. Only very generic 'things' go here.
    """

    format_type = {'X509 PEM Bundle': 0,
                   'X509 PEM Certificate only': 1,
                   'X509 PEM Intermediate certificate only': 2,
                   'PKCS#7 PEM Bundle': 3,
                   'PKCS#7 DER Bundle': 4}

    formats = {'AOL': 1,
               'Apache/ModSSL': 2,
               'Apache-SSL': 3,
               'C2Net Stronghold': 4,
               'Cisco 3000 Series VPN Concentrator': 33,
               'Citrix': 34,
               'Cobalt Raq': 5,
               'Covalent Server Software': 6,
               'IBM HTTP Server': 7,
               'IBM Internet Connection Server': 8,
               'iPlanet': 9,
               'Java Web Server (Javasoft / Sun)': 10,
               'Lotus Domino': 11,
               'Lotus Domino Go!': 12,
               'Microsoft IIS 1.x to 4.x': 13,
               'Microsoft IIS 5.x and later': 14,
               'Netscape Enterprise Server': 15,
               'Netscape FastTrac': 16,
               'Novell Web Server': 17,
               'Oracle': 18,
               'Quid Pro Quo': 19,
               'R3 SSL Server': 20,
               'Raven SSL': 21,
               'RedHat Linux': 22,
               'SAP Web Application Server': 23,
               'Tomcat': 24,
               'Website Professional': 25,
               'WebStar 4.x and later': 26,
               'WebTen (from Tenon)': 27,
               'Zeus Web Server': 28,
               'Ensim': 29,
               'Plesk': 30,
               'WHM/cPanel': 31,
               'H-Sphere': 32,
               'OTHER': -1,
               }

    status_code = {1: 'Certificate available',
                   2: 'Certificates Attached',
                   0: 'Certificate being processed by Comodo',
                   -10: 'The CSR cannot be decoded!',
                   -11: 'The CSR uses an unsupported algorithm!',
                   -12: 'The CSR has an invalid signature!',
                   -13: 'The CSR uses an unsupported key size!',
                   -14: 'An unknown error occurred!',
                   -16: 'Permission denied!',
                   -20: 'The certificate request has been rejected!',
                   -21: 'The certificate has been revoked!',
                   -22: 'Still awaiting payment!',
                   -31: 'The email is not a valid email.',
                   -32: 'The two phrase should be the same!',
                   -33: 'The Comodo certificate type is invalid!',
                   -34: 'The secret key is invalid!',
                   -35: 'The server type is invalid!',
                   -36: 'The term is invalid for customer type!',
                   -40: 'Invalid ID',
                   -100: 'Invalid authentication data for customer',
                   -101: 'Invalid authentication data for customer Organization',
                   -110: 'Domain is not allowed for customer',
                   -111: 'Domain is not allowed for customer Organization',
                   -120: 'Customer configuration is not allowed the requested action',
                   }


class ComodoTLSService(ComodoCA):
    """
    Class that encapsulates methods to use against Comodo SSL/TLS certificates
    """
    def __init__(self, **kwargs):
        """
        :param string api_url: The full URL for the API server
        :param int    ca_poll_wait: The period of time in seconds to wait until polling the CA for cert availability
        :param string customer_login_uri: The URI for the customer login (if your login to the Comodo GUI is at
                https://hard.cert-manager.com/customer/foo/, your login URI is 'foo').
        :param string org_id: The organization ID
        :param string password: The API user's password
        :param string secret_key: The API user's secret key
        :param string login: The API user
        """
        # Using get for consistency and to allow defaults to be easily set
        self.api_url = kwargs.get('api_url')
        self.customer_login_uri = kwargs.get('customer_login_uri')
        self.login = kwargs.get('login')
        self.org_id = kwargs.get('org_id')
        self.password = kwargs.get('password')
        self.secret_key = kwargs.get('secret_key')
        self.client_cert_auth = kwargs.get('client_cert_auth')
        self.session = Session()
        self.transport = Transport(session=self.session)
        self.client = Client(self.api_url, transport=self.transport)
        # Because Comodo is crap at designing APIs (in my opinion) we have to get the wsdl
        # then modify the transport to use client certs after that.
        if self.client_cert_auth:
            self.client_public_certificate = kwargs.get('client_public_certificate')
            self.client_private_key = kwargs.get('client_private_key')
            self.session.cert = (self.client_public_certificate, self.client_private_key)
        self.type_factory = self.client.type_factory('ns0')
        self.auth = self.type_factory.AuthData()
        self.auth.login = self.login
        self.auth.password = self.password
        self.auth.customerLoginUri = self.customer_login_uri

    def get_cert_types(self):
        """
        Collect the certificate types that are available to the customer.

        :return: A list of dictionaries of certificate types
        :rtype: list
        """
        result = self.client.service.getCustomerCertTypes(authData=self.auth)

        # Very basic error checking
        if result.statusCode != 0:
            print(ComodoCA.status_code[result.statusCode])
        else:
            return result.types

    def poll(self, format_type, id):
        """
        Poll for certificate availability after submission.

        :return: A string indicating the return collected from Comodo API, and a system exit code.
        :rtype: string
        """

        result = self.client.service.collect(authData=self.auth, id=id,
                                             formatType=ComodoCA.format_type[format_type])

        if result['statusCode'] == 2:
            print(result['SSL']['certificate'])
            sys.exit(0)
        elif result['statusCode'] == 0:
            print(self.ca_poll_wait)
            print(self.env['CERTMONGER_CA_COOKIE'])
            sys.exit(5)
        else:
            print(ComodoCA.status_code[result.statusCode])
            sys.exit(3)

        # Should never be reached
        return None

    def submit(self, cert_type_name, csr, revoke_password, term, subject_alt_names='',
               server_type='OTHER'):
        """
        Submit a certificate request to Comodo.

        :param string cert_type_name: The full cert type name (Example: 'PlatinumSSL Certificate')
        :param string revoke_password: A password for certificate revocation
        :param int term: The length, in years, for the certificate to be issued
        :param string subject_alt_names: Subject Alternative Names separated by a ",".
        :param string server_type: The type of server for the TLS certificate e.g 'Apache/ModSSL'
        :return: A string indicating the certificate ID to be collected (or the error message), and a system exit code.
        :rtype: string
        """

        cert_types = self.get_cert_types()

        for type in cert_types:
            if type.name == cert_type_name:
                cert_type = type

        result = self.client.service.enroll(authData=self.auth, orgId=self.org_id, secretKey=self.secret_key,
                                            csr=csr, phrase=revoke_password,
                                            subjAltNames=subject_alt_names,
                                            certType=cert_type, numberServers=1,
                                            serverType=ComodoCA.formats[server_type], term=term, comments='')

        if result > 0:
            return result
        else:
           return ComodoCA.status_code[result.statusCode]

        # Should never be reached
        return None