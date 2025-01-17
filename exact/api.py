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
            self.minutely_limit = int(response.headers.get("X-RateLimit-Minutely-Limit", 0))
            self.minutely_limit_remaining = int(
                response.headers.get("X-RateLimit-Minutely-Remaining", 0)
            )


class Resource(object):
    resource = ""
    DoesNotExist = DoesNotExist
    MultipleObjectsReturned = MultipleObjectsReturned

    def __init__(self, api):
        self._api = api

    # i am not using *args, and **kwargs (would be more generic) to make autocomplete/hints in IDE work better
    def filter(
        self, filter_string=None, select=None, order_by=None, limit=None, expand=None
    ):
        return self._api.filter(
            self.resource,
            filter_string=filter_string,
            select=select,
            order_by=order_by,
            limit=limit,
            expand=expand,
        )

    def get(self, filter_string=None, select=None, expand=None):
        return self._api.get(
            self.resource, filter_string=filter_string, select=select, expand=expand
        )

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
        # we keep track of the request limits exactonline poses
        self.limits = Limits()

        # there are some predefined apis
        self.accounts = Accounts(self)
        self.costcenters = Costcenters(self)
        self.costunits = Costunits(self)
        self.glaccounts = GLAccounts(self)
        self.sales = PurchaseEntries(self)
        self.purchases = PurchaseEntries(self)

    def get_session(self, *property_names):
        if not Session.objects.filter(**EXACT_SETTINGS).exists():
            Session.objects.create(**EXACT_SETTINGS)

        if property_names:
            qs = Session.objects.values_list(*property_names)
        else:
            qs = Session.objects

        return qs.get(**EXACT_SETTINGS)

    def get_auth_url(self):
        client_id, redirect_uri, api_url = self.get_session(
            "client_id", "redirect_uri", "api_url"
        )
        params = {
            "client_id": client_id,
            "redirect_uri": force_text(redirect_uri),
            "response_type": "code",
        }
        return api_url + "/oauth2/auth?" + urlencode(params)

    def _get_or_refresh_token(self, params):
        logger.debug("getting refresh token: params=%s", params)
        api_url, = self.get_session("api_url")
        response = requests.post(
            api_url + "/oauth2/token",
            data=params,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code != 200:
            logger.error(
                "Refresh token failed reason: %s, url: %s, headers: %s, body: %s",
                response.reason,
                response.url,
                response.request.headers,
                response.request.body,
            )
            msg = (
                "unexpected response while getting/refreshing token: %s" % response.text
            )
            raise ExactException(msg, response, self.limits)

        decoded = response.json()

        # update exactonline session
        session = self.get_session()
        session.access_token = decoded["access_token"]
        session.refresh_token = decoded["refresh_token"]
        # TODO: use access_expiry to avoid an unnecessary request if we know we will need to re-auth
        session.access_expiry = int(decoded["expires_in"])
        session.save()

    def get_token(self):
        logger.debug("getting token")
        client_id, client_secret, authorization_code, redirect_uri = self.get_session(
            "client_id", "client_secret", "authorization_code", "redirect_uri"
        )
        params = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": authorization_code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        self._get_or_refresh_token(params)

    def refresh_token(self):
        logger.debug("refreshing token")
        client_id, client_secret, refresh_token = self.get_session(
            "client_id", "client_secret", "refresh_token"
        )
        params = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        self._get_or_refresh_token(params)

    def _perform_request(self, method, url, data=None, params=None, re_auth=True):
        # retrive authorization on every request in case multiple processes are
        # using exactonline.
        access_token, = self.get_session("access_token")
        headers = {
            "Authorization": "Bearer %s" % access_token,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }
        logger.debug(
            "Performing %s request: %s, params: %s, data: %s, headers: %s",
            method,
            url,
            params,
            data,
            headers,
        )
        response = requests.request(
            method, url, data=data, params=params, headers=headers
        )

        if re_auth and response.status_code == 401:
            self.refresh_token()
            # use new auth-header
            access_token, = self.get_session("access_token")
            headers.update({"Authorization": "Bearer %s" % access_token})
            response = requests.request(
                method, url, data=data, params=params, headers=headers
            )

        self.limits.update(response)
        response.raise_for_status()
        return response

    def _send(self, method, resource, data=None, params=None):
        api_url, division = self.get_session("api_url", "division")
        url = "%s/v1/%s/%s" % (api_url, division, resource)
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
        api_url, = self.get_session("api_url")
        url = "%s%s" % (api_url, path)
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
