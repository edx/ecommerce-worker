""" Braze Client functions. """
import requests

from __future__ import absolute_import
from celery.utils.log import get_task_logger

from ecommerce_worker.braze.v1.exceptions import (
    ConfigurationError,
    BrazeNotEnabled,
    BrazeClientError,
    BrazeRateLimitError,
    BrazeInternalServerError
)
from ecommerce_worker.utils import get_configuration

log = get_task_logger(__name__)

DEFAULT_API_URL = "https://rest.iad-06.braze.com"
MESSAGES_SEND_ENDPOINT = "/messages/send"


def get_braze_configuration(site_code):
    """ Returns the Braze configuration for the specified site. """
    config = get_configuration('BRAZE', site_code=site_code)
    return config


def get_braze_client(site_code):
    """
    Returns a Braze client for the specified site.

    Args:
        site_code (str): Site for which the client should be configured.

    Returns:
        BrazeClient

    Raises:
        BrazeNotEnabled: If Braze is not enabled for the specified site.
        ConfigurationError: If either the Braze API key or secret are not set for the site.
    """
    # Get configuration
    config = get_braze_configuration(site_code)

    # Return if Braze integration disabled
    if not config.get('BRAZE_ENABLE'):
        msg = 'Braze is not enabled for site {}'.format(site_code)
        log.debug(msg)
        raise BrazeNotEnabled(msg)

    # Make sure key and secret configured
    key = config.get('BRAZE_KEY')
    secret = config.get('BRAZE_SECRET')

    if not (key and secret):
        msg = 'Both key and secret are required for site {}'.format(site_code)
        log.error(msg)
        raise ConfigurationError(msg)

    return BrazeClient(key, secret)


class BrazeClient(object):
    """
    Client for Braze REST API
    """

    def __init__(self, api_key, api_url=None):
        self.api_key = api_key
        self.api_url = api_url or DEFAULT_API_URL
        self.session = requests.Session()
        self.request_url = ""

    def __create_request(self, payload):

        payload["api_key"] = self.api_key

        response = {"errors": []}
        r = self._post_request(payload)
        response.update(r.json())
        response["status_code"] = r.status_code

        message = response["message"]
        response["success"] = (
            message in ("success", "queued") and not response["errors"]
        )

        if message != "success":
            raise BrazeClientError(message, response["errors"])

        if "status_code" not in response:
            response["status_code"] = 0

        if "message" not in response:
            response["message"] = ""

        return response

    def _post_request(self, payload):
        """
        :param dict payload:
        :rtype: requests.Response
        """
        r = self.session.post(self.request_url, json=payload, timeout=2)
        if r.status_code == 429:
            reset_epoch_s = float(r.headers.get("X-RateLimit-Reset", 0))
            raise BrazeRateLimitError(reset_epoch_s)
        elif str(r.status_code).startswith("5"):
            raise BrazeInternalServerError
        return r

    def send_message(
        self,
        user_aliases=None,
        messages=None,
    ):
        """
        :return: json dict response, for example: {"message": "success", "errors": [], "client_error": ""}
        """
        self.request_url = self.api_url + MESSAGES_SEND_ENDPOINT

        payload = {}

        if user_aliases is not None:
            payload["user_aliases"] = user_aliases
        if messages is not None:
            payload["messages"] = messages

        return self.__create_request(payload)
