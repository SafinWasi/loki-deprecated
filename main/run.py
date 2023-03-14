from loki import Loki
import os

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