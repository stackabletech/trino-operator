"""Perform the OpenID Connect authentication flow to access a given page.

This script opens a given URL and expects to be redirected to a
Keycloak login page. It extracts the login action from the HTML content
of the Keycloak page and posts the credentials of a test user to it.
Finally it tests that Keycloak redirects back to the original page.
"""
import logging
import requests
import urllib3
from html.parser import HTMLParser
import sys


class KCLoginParser(HTMLParser):
    """ Extract the Keycloak url to perform the user login
        and be redirected to Druid.
    """

    kc_action: str = ""

    def __init__(self):
        HTMLParser.__init__(self)

    def handle_starttag(self, tag, attrs):
        if "form" == tag:
            for name, value in attrs:
                if "action" == name:
                    logging.debug(f"found redirect action {value}")
                    self.kc_action = value


def test_login_flow(login_url):
    session = requests.Session()

    result = session.get(
        login_url,
        verify=False,
        allow_redirects=True,
    )

    result.raise_for_status()

    kcLoginParser = KCLoginParser()
    kcLoginParser.feed(result.text)

    if not kcLoginParser.kc_action:
        raise ValueError("Failed to extract Keycloak action URL")

    result = session.post(kcLoginParser.kc_action,
                          data={
                              "username": "test",
                              "password": "test",
                          },
                          verify=False,
                          allow_redirects=True,
                          )

    result.raise_for_status()

    location = result.url
    code = result.status_code
    if not (code == 200 and location == login_url):
        raise ValueError(
            f"Expected to land on the Druid console but ended at [{location}]")


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
