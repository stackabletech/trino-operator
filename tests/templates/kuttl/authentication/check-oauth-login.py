"""Perform the OpenID Connect authentication flow to access a given page.

This script opens a given URL and expects to be redirected to a
Keycloak login page. It extracts the login action from the HTML content
of the Keycloak page and posts the credentials of a test user to it.
Finally it tests that Keycloak redirects back to the original page.
"""
import logging
import requests
import sys
import urllib3
from bs4 import BeautifulSoup


def test_login_flow(login_url):
    session = requests.Session()

    result = session.get(login_url)

    result.raise_for_status()

    html = BeautifulSoup(result.text, 'html.parser')
    authenticate_url = html.form['action']
    result = session.post(authenticate_url, data={
        'username': "test",
        'password': "test"
    })

    result.raise_for_status()

    assert result.url == login_url, \
        "Redirection to the Trino UI expected"


def main():
    logging.basicConfig(level=logging.DEBUG)
    # disable a warning (InsecureRequestWarning) because it's just noise here
    urllib3.disable_warnings()

    login_url = sys.argv[1]

    assert len(login_url) > 0

    test_login_flow(login_url)

    logging.info("Success!")


if __name__ == "__main__":
    main()
