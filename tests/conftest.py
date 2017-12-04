import betamax
import os
from betamax_serializers import pretty_json

betamax.Betamax.register_serializer(pretty_json.PrettyJSONSerializer)

customer_login_uri = os.environ.get('CUSTOMER_LOGIN_URI', 'comodo')
login = os.environ.get('LOGIN', 'comodo')
org_id = os.environ.get('ORG_ID', '1234')
password = os.environ.get('PASSWORD', 'fubar')
secret_key = os.environ.get('SECRET_KEY', 'fubar')

with betamax.Betamax.configure() as config:
    config.cassette_library_dir = 'tests/integration/cassettes'
    config.default_cassette_options['serialize_with'] = 'prettyjson'
    config.define_cassette_placeholder('<CUSTOMER_LOGIN_URI>', customer_login_uri)
    config.define_cassette_placeholder('<LOGIN>', login)
    config.define_cassette_placeholder('<ORG_ID>', org_id)
    config.define_cassette_placeholder('<PASSWORD>', password)
    config.define_cassette_placeholder('<SECRET_KEY>', secret_key)
