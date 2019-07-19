# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import logging
from datetime import datetime

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.serializers.json import DjangoJSONEncoder
from django.utils.http import urlencode
from django.utils.encoding import force_text
import requests

from exact.models import Session


logger = logging.getLogger("exact")


def _get(option):
    try:
        return getattr(settings, "EXACT_ONLINE_" + option)
    except AttributeError:
        raise ImproperlyConfigured("Exact: Setting '%s' not found!" % option)


EXACT_SETTINGS = {
    "redirect_uri": _get("REDIRECT_URI"),
    "client_id": _get("CLIENT_ID"),
    "client_secret": _get("CLIENT_SECRET"),
    "api_url": _get("API_URL"),
    "division": _get("DIVISION"),
}


class ExactException(Exception):
    def __init__(self, message, response, limits):
        super(ExactException, self).__init__(message)
        self.response = response
        self.limits = limits

    def __str__(self):
        return "%s, limit reached? %s" % (
            super(ExactException, self).__str__(),
            self.limits.is_limit_reached,
        )


class DoesNotExist(Exception):
    pass


class MultipleObjectsReturned(Exception):
    pass


class Limits(object):
    def __init__(self):
        self.daily_limit = None
        self.daily_limit_remaining = None
        self.daily_limit_reset = None
        self.minutely_limit = None
        self.minutely_limit_remaining = None

    @property
    def is_limit_reached(self):
        return self.minutely_limit_remaining == 0 or self.daily_limit_remaining == 0

    def update(self, response):
        if (
            "X-RateLimit-Limit" in response.headers
        ):  # errors responses do not carry these headers
            self.daily_limit = int(response.headers["X-RateLimit-Limit"])
            self.daily_limit_remaining = int(response.headers["X-RateLimit-Remaining"])
            self.daily_limit_reset = datetime.utcfromtimestamp(
                int(response.headers["X-RateLimit-Reset"]) / 1000
            )
            self.minutely_limit = int(response.headers["X-RateLimit-Minutely-Limit"])
            self.minutely_limit_remaining = int(
                response.headers["X-RateLimit-Minutely-Remaining"]
            )


class Resource(object):
    resource = ""
    DoesNotExist = DoesNotExist
    MultipleObjectsReturned = MultipleObjectsReturned

    def __init__(self, api):
        self._api = api

    # i am not using *args, and **kwargs (would be more generic) to make autocomplete/hints in IDE work better
    def filter(self, filter_string=None, select=None, order_by=None, limit=None, expand=None):
        return self._api.filter(
            self.resource,
            filter_string=filter_string,
            select=select,
            order_by=order_by,
            limit=limit,
            expand=expand,
        )

    def get(self, filter_string=None, select=None, expand=None):
        return self._api.get(self.resource, filter_string=filter_string, select=select, expand=expand)

    def create(self, data):
        return self._api.create(self.resource, data)

    def update(self, guid, data):
        return self._api.update(self.resource, guid, data)

    def delete(self, guid):
        return self._api.delete(self.resource, guid)


# example of simplifying some resources
class GetByCodeMixin(object):
    def get(self, code=None, filter_string=None, select=None, expand=None):
        if code is not None:
            if filter_string:
                filter_string += " and Code eq '%s'" % code
            else:
                filter_string = "Code eq '%s'" % code
        return super(GetByCodeMixin, self).get(
            filter_string=filter_string, select=select, expand=expand
        )


class Accounts(GetByCodeMixin, Resource):
    resource = "crm/Accounts"

    def get(self, code=None, filter_string=None, select=None, expand=None):
        if code is not None:
            code = "%18s" % code
        return super(Accounts, self).get(code, filter_string, select, expand)


class Costcenters(GetByCodeMixin, Resource):
    resource = "hrm/Costcenters"


class Costunits(GetByCodeMixin, Resource):
    resource = "hrm/Costunits"


class GLAccounts(GetByCodeMixin, Resource):
    resource = "financial/GLAccounts"


class PurchaseEntries(Resource):
    resource = "purchaseentry/PurchaseEntries"

    # pylint: disable=arguments-differ
    def get(self, entry_number=None, filter_string=None, select=None):
        if entry_number is not None:
            if filter_string:
                filter_string += " and EntryNumber eq %d" % entry_number
            else:
                filter_string = "EntryNumber eq %d" % entry_number
        return super(PurchaseEntries, self).get(filter_string, select)


class SalesEntries(PurchaseEntries):
    resource = "salesentry/SalesEntries"


class Exact(object):
    DoesNotExist = DoesNotExist
    MultipleObjectsReturned = MultipleObjectsReturned

    def __init__(self):
        # we try to reuse the connection
        self.requests_session = requests.Session()
        self.requests_session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": "Bearer %s" % self.session.access_token,
                "Content-Type": "application/json",
                "Prefer": "return=representation",
            }
        )

        # we keep track of the request limits exactonline poses
        self.limits = Limits()

        # there are some predefined apis
        self.accounts = Accounts(self)
        self.costcenters = Costcenters(self)
        self.costunits = Costunits(self)
        self.glaccounts = GLAccounts(self)
        self.sales = PurchaseEntries(self)
        self.purchases = PurchaseEntries(self)

    @property
    def session(self):
        s, _ = Session.objects.get_or_create(**EXACT_SETTINGS)
        return s

    @property
    def auth_url(self):
        params = {
            "client_id": self.session.client_id,
            "redirect_uri": force_text(self.session.redirect_uri),
            "response_type": "code",
        }
        return self.session.api_url + "/oauth2/auth?" + urlencode(params)

    def _get_or_refresh_token(self, params):
        logger.debug("getting refresh token: params=%s", params)
        response = requests.post(self.session.api_url + "/oauth2/token", data=params, headers={
            "Content-Type": "application/x-www-form-urlencoded",
        })

        if response.status_code != 200:
            logger.error(
                "Refresh token failed reason: %s, url: %s, headers: %s, data: %s",
                response.reason,
                response.url,
                response.request.headers,
                response.request.data
            )
            msg = (
                "unexpected response while getting/refreshing token: %s" % response.text
            )
            raise ExactException(msg, response, self.limits)

        decoded = response.json()

        # update exactonline session
        session = self.session
        session.access_token = decoded["access_token"]
        session.refresh_token = decoded["refresh_token"]
        # TODO: use access_expiry to avoid an unnecessary request if we know we will need to re-auth
        session.access_expiry = int(decoded["expires_in"])
        session.save()

        # renew connection and update headers
        requests_session = requests.Session()
        requests_session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": "Bearer %s" % session.access_token,
                "Content-Type": "application/json",
                "Prefer": "return=representation",
            }
        )
        self.requests_session = requests_session

    def get_token(self):
        logger.debug("getting token")
        params = {
            "client_id": self.session.client_id,
            "client_secret": self.session.client_secret,
            "code": self.session.authorization_code,
            "grant_type": "authorization_code",
            "redirect_uri": self.session.redirect_uri,
        }
        self._get_or_refresh_token(params)

    def refresh_token(self):
        logger.debug("refreshing token")
        params = {
            "client_id": self.session.client_id,
            "client_secret": self.session.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": self.session.refresh_token,
        }
        self._get_or_refresh_token(params)

    def _perform_request(self, method, url, data=None, params=None, re_auth=True):
        # retrive authorization on every request in case multiple processes are
        # using exactonline.
        headers = {"Authorization": "Bearer %s" % self.session.access_token}
        request = requests.Request(method, url, data=data, params=params, headers=headers)
        prepped = self.requests_session.prepare_request(request)

        logger.debug(
            "Performing %s request: %s, body: %s, headers: %s",
            prepped.method, prepped.url, prepped.body, prepped.headers
        )

        response = self.requests_session.send(prepped)
        if re_auth and response.status_code == 401:
            self.refresh_token()
            # use new auth-header
            request.headers = {"Authorization": "Bearer %s" % self.session.access_token}
            prepped = self.requests_session.prepare_request(request)
            logger.debug("sending request: %s", prepped.url)
            response = self.requests_session.send(prepped)

        self.limits.update(response)
        response.raise_for_status()
        return response

    def _send(self, method, resource, data=None, params=None):
        url = "%s/v1/%s/%s" % (self.session.api_url, self.session.division, resource)
        response = self._perform_request(method, url, data=data, params=params)
        # at this point we tried to re-auth, so anything but 200/OK, 201/Created or 204/no content is unexpected
        # yes: the exact documentation does not mention 204; returned on PUT anyways
        if response.status_code not in (200, 201, 204):
            msg = "Unexpected status code received. Expected one of (200, 201, 204), got %d\n\n%s"
            msg %= (response.status_code, response.text)
            logger.debug("%s\n%s", msg, response.text)
            raise ExactException(msg, response, self.limits)

        # don't try to decode json if we got nothing back
        if response.status_code == 204:
            return None
        # TODO: handle the case where they send a 200, with HTML "we're under maintenance". yes, they do that
        return response.json()

    def raw(self, method, path, data=None, params=None, re_auth=True):
        url = "%s%s" % (self.session.api_url, path)
        return self._perform_request(
            method, url, data=data, params=params, re_auth=re_auth
        )

    def get(self, resource, filter_string=None, select=None, expand=None):
        params = {
            "$top": 2,
            "$select": select or "*",
            "$filter": filter_string,
            "$inlinecount": "allpages",  # this forces a returned dict (otherwise we might get a list with one entry)
            "$expand": expand,
        }
        r = self._send("GET", resource, params=params)

        data = r["d"]["results"]
        if len(data) == 0:
            raise DoesNotExist("recource not found. params were: %r" % params)
        if len(data) > 1:
            raise MultipleObjectsReturned(
                "api returned multiple objects. params were: %r" % params
            )
        return data[0]

    def filter(
        self,
        resource,
        filter_string=None,
        select=None,
        order_by=None,
        limit=None,
        expand=None,
    ):
        params = {
            "$filter": filter_string,
            "$expand": expand,
            "$select": select,
            "$orderby": order_by,
            "$top": limit,
            "$inlinecount": "allpages",
        }
        response = self._send("GET", resource, params=params)
        results = response["d"]["results"]
        for r in results:
            yield r

        next_url = response["d"].get("__next")
        while next_url:
            raw_response = self._perform_request("GET", next_url)
            response = raw_response.json()
            next_url = response["d"].get("__next")
            results = response["d"]["results"]
            for r in results:
                yield r

    def create(self, resource, data):
        r = self._send("POST", resource, data=json.dumps(data, cls=DjangoJSONEncoder))
        return r["d"]

    def update(self, resource, guid, data):
        resource = "%s(guid'%s')" % (resource, guid)
        r = self._send("PUT", resource, data=json.dumps(data, cls=DjangoJSONEncoder))
        return r

    def delete(self, resource, guid):
        resource = "%s(guid'%s')" % (resource, guid)
        r = self._send("DELETE", resource)
        return r
