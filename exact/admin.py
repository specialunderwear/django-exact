# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django import forms
from django.contrib import admin

from .models import Session, Webhook


class SessionAdmin(admin.ModelAdmin):
    model = Session
    list_display = ["id", "api_url", "redirect_uri", "client_id"]


class WebhookAdmin(admin.ModelAdmin):
    model = Webhook
    list_display = ["topic", "callback"]

    def get_readonly_fields(self, request, obj=None):
        if obj:
            return ["topic"]
        else:
            return []


admin.site.register(Session, SessionAdmin)
admin.site.register(Webhook, WebhookAdmin)
