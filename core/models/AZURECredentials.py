from flask import Blueprint, request, Response
from database.models import AZURECredentials
import sys
from flask import Response, request
from flask_jwt_extended import create_access_token, jwt_required
import datetime
import flask_mongoengine
from core.enum_user_privs.getuid_aws import getuid

azurecredentials_blueprint = Blueprint('azurecredentials', __name__)

@azurecredentials_blueprint.route('/api/latest/azurecredentials', methods=['GET'])
@jwt_required()
def list_azurecredentials():
    azurecredentials = AZURECredentials.objects().to_json()
    return Response(azurecredentials, mimetype="application/json", status=200)


@azurecredentials_blueprint.route('/api/latest/azurecredentials/getuid', methods=['POST'])
@jwt_required()
def getuid_aws_creds():
    body = request.get_json()
    try:
        workspace = body['workspace']

        azurecredentials = AZURECredentials.objects.get(aws_profile_name=body.get('aws_profile_name'))

        return {'UserName': getuid(azurecredentials, workspace)}, 200
    except flask_mongoengine.DoesNotExist:
        return {'error': "Credentials do not exist"}, 404


@azurecredentials_blueprint.route('/api/latest/azurecredentials', methods=['POST'])
@jwt_required()
def get_azurecredentials():
    body = request.get_json()
    try:
        azurecredentials = AZURECredentials.objects.get(aws_profile_name=body.get('aws_profile_name'))

        return {'azurecredentials': azurecredentials}, 200
    except flask_mongoengine.DoesNotExist:
        return {'error': "Credentials do not exist"}, 404


@azurecredentials_blueprint.route('/api/latest/azurecredentials', methods=['PUT'])
@jwt_required()
def set_azurecredentials():
    body = request.get_json()

    try:
        # aws_creds = AZURECredentials.objects(**body).save()
        aws_creds = AZURECredentials(**body).save()
        return {"message": "Credentials of '{}' was created!".format(body['aws_profile_name'])}, 200

    except:
        if "Tried to save duplicate unique keys" in str(sys.exc_info()[1]):
            return {"error": "Credentials Exist", 'status_code': 1337}

        return {"error": str(sys.exc_info()[1])}, 500


@azurecredentials_blueprint.route('/api/latest/azurecredentials', methods=['DELETE'])
@jwt_required()
def delete_azurecredentials():
    try:
        body = request.get_json()
        azurecredentials_name = body['azurecredentials_name']
        AZURECredentials.objects.get_or_404(azurecredentials_name=azurecredentials_name).delete()
        return '', 200
    except:
        return sys.exc_info()[1], 500
