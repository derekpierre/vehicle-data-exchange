import dash_core_components as dcc
from dash.dependencies import Output, Input, State
import dash_html_components as html
import os

from app import app, SHARED_FOLDER, SEEDNODE_URL

from nucypher.characters.lawful import Bob, Ursula
from nucypher.config.characters import AliceConfiguration
from nucypher.config.constants import TEMPORARY_DOMAIN
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.network.middleware import RestMiddleware
from nucypher.utilities.logging import GlobalLoggerSettings

import datetime
import shutil
import maya
import json

from umbral.keys import UmbralPublicKey

POLICY_INFO_FILE = os.path.join(SHARED_FOLDER, "policy_metadata.json")

######################
# Boring setup stuff #
######################
#
# # Twisted Logger
GlobalLoggerSettings.start_console_logging()
#
# # Temporary file storage
TEMP_ALICE_DIR = "{}/alicia-files".format(os.path.dirname(os.path.abspath(__file__)))
TEMP_URSULA_CERTIFICATE_DIR = "{}/ursula-certs".format(TEMP_ALICE_DIR)

#######################################
# Alicia, the Authority of the Policy #
#######################################


# We get a persistent Alice.
passphrase = "TEST_ALICIA_INSECURE_DEVELOPMENT_PASSWORD"
try:  # If we had an existing Alicia in disk, let's get it from there
    alice_config_file = os.path.join(TEMP_ALICE_DIR, "config_root", "alice.config")
    new_alice_config = AliceConfiguration.from_configuration_file(
        filepath=alice_config_file,
        network_middleware=RestMiddleware(),
        start_learning_now=False,
        save_metadata=False,
    )
    alicia = new_alice_config(passphrase=passphrase)
except:  # If anything fails, let's create Alicia from scratch
    # Remove previous demo files and create new ones
    shutil.rmtree(TEMP_ALICE_DIR, ignore_errors=True)
    os.mkdir(TEMP_ALICE_DIR)
    os.mkdir(TEMP_URSULA_CERTIFICATE_DIR)

    ursula = Ursula.from_seed_and_stake_info(seed_uri=SEEDNODE_URL,
                                             federated_only=True,
                                             minimum_stake=0)

    alice_config = AliceConfiguration(
        config_root=os.path.join(TEMP_ALICE_DIR, "config_root"),
        domains={TEMPORARY_DOMAIN},
        known_nodes={ursula},
        start_learning_now=False,
        federated_only=True,
        learn_on_same_thread=True,
    )
    alice_config.initialize(password=passphrase)
    alice_config.keyring.unlock(password=passphrase)
    alicia = alice_config.produce()

    # We will save Alicia's config to a file for later use
    alice_config_file = alice_config.to_configuration_file()

# Let's get to learn about the NuCypher network
alicia.start_learning_loop(now=True)

layout = html.Div([
    html.Div([
        html.Img(src='./assets/nucypher_logo.png'),
    ], className='banner'),
    html.Div([
        html.Div([
            html.Div([
                html.Img(src='./assets/alicia.png'),
            ], className='two columns'),
            html.Div([
                html.Div([
                    html.H2('ALICIA'),
                    html.P('Alicia has a OBD device in her vehicle (Enrico) that obtains readings from a '
                           'variety of sensors and outputs this data in encrypted form. She thinks '
                           'that at some point in the future she may want to share this data with '
                           'her Insurance company.')
                ], className="row")
            ], className='five columns'),
        ], className='row'),
    ], className='app_name'),
    html.Hr(),
    html.Div([
        html.H3('Policy Key'),
        html.Button('Create Policy Key', id='create-policy-button', type='submit',
                    className='button button-primary', n_clicks=0, n_clicks_timestamp=0),
        html.Div(id='policy-key-response')
    ], className='row'),
    html.Hr(),
    html.Div([
        html.H3('Access Policy'),
        html.Div([
            html.Div('Policy Duration (Days): ', className='two columns'),
            dcc.Input(id='days', value='5', type='number', className='two columns'),
        ], className='row'),
        html.Div([
            html.Div('M-Threshold: ', className='two columns'),
            dcc.Input(id='m-value', value='1', type='number', className='two columns'),
        ], className='row'),
        html.Div([
            html.Div('N-Shares: ', className='two columns'),
            dcc.Input(id='n-value', value='1', type='number', className='two columns'),
        ], className='row'),
        html.Div([
            html.Div('Recipient Encrypting Key: ', className='two columns'),
            dcc.Input(id='recipient-pub-key-grant', type='text', className='seven columns'),
        ], className='row'),
        html.Div([
            html.Div('Recipient Verifying Key: ', className='two columns'),
            dcc.Input(id='recipient-ver-key-grant', type='text', className='seven columns')
        ], className='row'),
        html.Div([
            html.Button('Grant Access', id='grant-button', type='submit',
                        className='button button-primary', n_clicks=0, n_clicks_timestamp=0),
            html.Div(id='grant-response'),
        ], className='row'),
        html.Br(),
        html.Div([
            html.Div('Revoke Recipient Encrypting Key: ', className='two columns'),
            dcc.Input(id='recipient-pub-key-revoke', type='text', className='seven columns'),
        ], className='row'),
        html.Div([
            html.Button('Revoke Access', id='revoke-button', type='submit',
                        className='button button-primary', n_clicks=0, n_clicks_timestamp=0),
            html.Div(id='revoke-response', style={'color': 'red'}),
        ], className='row')
    ])
])

# store and track policies pub_key_hex -> policy
granted_policies = dict()

@app.callback(
    Output('policy-key-response', 'children'),
    [Input('create-policy-button', 'n_clicks')]
)
def create_policy(n_clicks):
    if n_clicks > 0:
        label = 'vehicle-data'
        label = label.encode()

        policy_pubkey = alicia.get_policy_encrypting_key_from_label(label)

        return "The policy encrypting key for " \
               "label '{}' is {}".format(label.decode('utf-8'), policy_pubkey.to_bytes().hex())


@app.callback(
    Output('grant-response', 'children'),
    [Input('grant-button', 'n_clicks'),
     Input('revoke-button', 'n_clicks')],
    [State('grant-button', 'n_clicks_timestamp'),
     State('revoke-button', 'n_clicks_timestamp'),
     State('days', 'value'),
     State('m-value', 'value'),
     State('n-value', 'value'),
     State('recipient-pub-key-grant', 'value'),
     State('recipient-ver-key-grant', 'value')]
)
def grant_access(grant_n_clicks, revoke_n_clicks, grant_time, revoke_time, days, m, n, recipient_pubkey_hex, recipient_verkey_hex):
    label = b'vehicle-data'

    if revoke_time >= grant_time:
        # either triggered at start or because revoke was executed
        return ''

    enc_key = UmbralPublicKey.from_bytes(bytes.fromhex(recipient_pubkey_hex))
    sig_key = UmbralPublicKey.from_bytes(bytes.fromhex(recipient_verkey_hex))

    powers_and_material = {
        DecryptingPower: enc_key,
        SigningPower: sig_key
    }

    # We create a view of the Bob who's going to be granted access.
    bob = Bob.from_public_keys(powers_and_material=powers_and_material,
                               federated_only=True)

    # Here are our remaining Policy details, such as:
    # - Policy duration
    policy_end_datetime = maya.now() + datetime.timedelta(days=int(days))

    # - m-out-of-n: This means Alicia splits the re-encryption key in 5 pieces and
    #               she requires Bob to seek collaboration of at least 3 Ursulas
    # With this information, Alicia creates a policy granting access to Bob.
    # The policy is sent to the NuCypher network.
    print("Creating access policy for the Doctor...")
    policy = alicia.grant(bob=bob,
                          label=label,
                          m=int(m),
                          n=int(n),
                          expiration=policy_end_datetime)
    print("Done!")

    # For the demo, we need a way to share with Bob some additional info
    # about the policy, so we store it in a JSON file
    policy_info = {
        "policy_encrypting_key": policy.public_key.to_bytes().hex(),
        "alice_verifying_key": bytes(alicia.stamp).hex(),
        "label": label.decode("utf-8"),
    }

    with open(POLICY_INFO_FILE, 'w') as f:
        json.dump(policy_info, f)

    granted_policies[recipient_pubkey_hex] = policy

    return 'Access granted to recipient with encryption key: {}!'.format(recipient_pubkey_hex)


@app.callback(
    Output('revoke-response', 'children'),
    [Input('revoke-button', 'n_clicks'),
     Input('grant-button', 'n_clicks')],
    [State('grant-button', 'n_clicks_timestamp'),
     State('revoke-button', 'n_clicks_timestamp'),
     State('recipient-pub-key-revoke', 'value')]
)
def revoke_access(revoke_n_clicks, grant_n_clicks, grant_time, revoke_time, recipient_pubkey_hex):
    if grant_time >= revoke_time:
        # either triggered at start or because grant was executed
        return ''

    policy = granted_policies.pop(recipient_pubkey_hex, None)
    if policy is None:
        return f'Policy has not been previously granted for recipient with encryption key {recipient_pubkey_hex}'

    print("Revoking access to recipient", recipient_pubkey_hex)
    try:
        failed_revocations = alicia.revoke(policy=policy)
        if failed_revocations:
            return 'WARNING: Access revoked to recipient with encryption key {} - but {} nodes failed to revoke' \
                .format(recipient_pubkey_hex, len(failed_revocations))

        return f'Access revoked to recipient with encryption key {recipient_pubkey_hex}!'
    finally:
        os.remove(POLICY_INFO_FILE.format(recipient_pubkey_hex))
