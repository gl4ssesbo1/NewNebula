import json
import sys
import requests
import random
import string
from flask_mongoengine import DoesNotExist
import datetime

from database.models import AZURECredentials

author = {
    "name": "gl4ssesbo1",
    "twitter": "https://twitter.com/gl4ssesbo1",
    "github": "https://github.com/gl4ssesbo1",
    "blog": "https://www.pepperclipp.com/"
}

needs_creds = True

variables = {
    "SERVICE": {
        "value": "none",
        "required": "true",
        "description": "The service that will be used to run the module. It cannot be changed."
    }
}

global device_code_request_json

description = "This module will try to get as many information on the user's account on O365, based on the its privileges."
aws_command = "No cli command"

def exploit(profile, workspace):
    access_token = profile['azure_access_token']
    all_return_dict = {}

    # --------------------------------------------------
    # Get user's Info
    # --------------------------------------------------
    try:
        me = json.loads(requests.get("https://graph.microsoft.com/v1.0/me",
                           headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer {}'.format(access_token)
                           }).text
                        )
        access_token['basic_info'] = me
    except:
        pass

    # --------------------------------------------------
    # Get user's privileges on graph api
    # --------------------------------------------------
    try:
        me = json.loads(requests.get("https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants",
                           headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer {}'.format(access_token)
                           }).text
                        )
        access_token['oauth_permissions_grants'] = me
    except:
        pass


    # --------------------------------------------------
    # Get user's Mail
    # --------------------------------------------------
    try:
        me = json.loads(requests.get("https://graph.microsoft.com/v1.0/me/mailfolders",
                           headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer {}'.format(access_token)
                           }).text
                        )
        access_token['mail_folders'] = me
    except:
        pass

    # --------------------------------------------------
    # Get user's Mail
    # --------------------------------------------------
    try:
        me = json.loads(requests.get("https://graph.microsoft.com/v1.0/me",
                           headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer {}'.format(access_token)
                           }).text
                        )
        access_token['basic_info'] = me
    except:
        pass

    # --------------------------------------------------
    # Get user's Mail
    # --------------------------------------------------
    try:
        me = json.loads(requests.get("https://graph.microsoft.com/v1.0/me",
                           headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer {}'.format(access_token)
                           }).text
                        )
        access_token['basic_info'] = me
    except:
        pass

    # --------------------------------------------------
    # Get user's Mail
    # --------------------------------------------------
    try:
        me = json.loads(requests.get("https://graph.microsoft.com/v1.0/me",
                           headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer {}'.format(access_token)
                           }).text
                        )
        access_token['basic_info'] = me
    except:
        pass

    # --------------------------------------------------
    # Get user's Mail
    # --------------------------------------------------
    try:
        me = json.loads(requests.get("https://graph.microsoft.com/v1.0/me",
                           headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer {}'.format(access_token)
                           }).text
                        )
        access_token['basic_info'] = me
    except:
        pass

    # --------------------------------------------------
    # Get user's Mail
    # --------------------------------------------------
    try:
        me = json.loads(requests.get("https://graph.microsoft.com/v1.0/me",
                           headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer {}'.format(access_token)
                           }).text
                        )
        access_token['basic_info'] = me
    except:
        pass

    # --------------------------------------------------
    # Get user's Mail
    # --------------------------------------------------
    try:
        me = json.loads(requests.get("https://graph.microsoft.com/v1.0/me",
                           headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer {}'.format(access_token)
                           }).text
                        )
        access_token['basic_info'] = me
    except:
        pass

    # --------------------------------------------------
    # Get user's Mail
    # --------------------------------------------------
    try:
        me = json.loads(requests.get("https://graph.microsoft.com/v1.0/me",
                           headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer {}'.format(access_token)
                           }).text
                        )
        access_token['basic_info'] = me
    except:
        pass

    # --------------------------------------------------
    # Get user's Mail
    # --------------------------------------------------
    try:
        me = json.loads(requests.get("https://graph.microsoft.com/v1.0/me",
                           headers={
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer {}'.format(access_token)
                           }).text
                        )
        access_token['basic_info'] = me
    except:
        pass

def send_email(email, device_code):
    print(email, device_code)

