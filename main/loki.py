"""
Loki
Command-line Python OpenID Connect Client

"""

from oauthlib.oauth2 import WebApplicationClient, BackendApplicationClient
from requests_oauthlib.oauth2_session import OAuth2Session
import requests
import os, sys

import logging, os
from dotenv import load_dotenv
import structlog

load_dotenv()
log_level = os.getenv("LOG_LEVEL", "INFO")
log_level = logging.getLevelName(log_level)

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper("iso"),
        structlog.dev.ConsoleRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(log_level),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=False
)

log = structlog.get_logger()



cls = lambda:os.system('cls' if os.name=='nt' else 'clear')


class Loki:
    def __init__(self, host, client_id, client_secret, verify_ssl=True):
        cls()
        print("Initializing Loki")
        self.host = host
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl
        self.openid_configuration = self.load_wellknown()

    def start_flow(self):
        if not self.verify_ssl:
            log.warning("VERIFY_SSL set to False. It is STRONGLY recommended to use HTTPS for OAuth2.")
        choice = None
        while choice == None:
            print("\t 1: Authorization Code Grant")
            print("\t 2: Client Credentials Grant")
            print("\t 3: Implicit Grant")
            print("\t 4: Hybrid Grant")
            print("Please select flow: ", end="")
            choice = input()
            try:
                choice = int(choice)
                if choice < 1 or choice > 4:
                    cls()
                    print("Invalid input, please choose [1-4]")
                    choice = None
            except Exception:
                cls()
                print("Invalid input, please choose [1-4]")
                choice = None
        if choice == 1:
            token = self.authorization_code()
        elif choice == 2:
            token = self.client_credentials()
        elif choice == 3:
            token = self.implicit()
        else:
            token = self.hybrid()
        if token:
            print(f"Access token obtained: {token['access_token']}")
        else:
            return


    def client_credentials(self):
        print("Enter scopes separated by a space: ", end="")
        scopes = input()
        scopeArray = scopes.split(" ")
        client = BackendApplicationClient(self.client_id, scope=scopeArray)
        self.client = OAuth2Session(client=client)
        try:
            token = self.client.fetch_token(self.openid_configuration["token_endpoint"], client_secret=self.client_secret)
            log.debug(token)
        except Exception as e:
            log.error(f"Authentication failed: {e}")
            return None
        return token

    def authorization_code(self):
        log.error("Not yet implemented")
        raise NotImplementedError

    def implicit(self):
        log.error("Not yet implemented")
        raise NotImplementedError

    def hybrid(self):
        log.error("Not yet implemented")
        raise NotImplementedError
    
    def load_wellknown(self):
        response = requests.get(f"{self.host}/.well-known/openid-configuration")
        response.raise_for_status()
        return response.json()

if __name__ == '__main__':
    host = os.getenv("HOST")
    client_id = os.getenv("CLIENT_ID")
    client_secret = os.getenv("CLIENT_SECRET")
    verify_ssl = os.getenv("VERIFY_SSL", "True")
    if verify_ssl == "True":
        verify_ssl = True
    else:
        verify_ssl = False
    loki = Loki(host, client_id, client_secret)
    loki.start_flow()