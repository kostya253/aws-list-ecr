import sys
import os
import math
import subprocess
import multiprocessing

from time import time, sleep
import webbrowser
import boto3
from boto3.session import Session


def listAccounts(found_token, sso, sso_token):
    if found_token:
        accounts = sso.list_accounts(nextToken=found_token, accessToken=sso_token)
    else:
        accounts = sso.list_accounts(accessToken=sso_token)
    return accounts


def ssoListAccounts(sso, sso_token):
    records = []
    more_objects = True
    found_token = ""
    while more_objects:
        accounts = listAccounts(found_token, sso, sso_token)
        for account in accounts["accountList"]:
            if "accountId" in account:
                records.append(account["accountId"])

        # Now check there is more objects to list
        if "nextToken" in accounts:
            found_token = accounts["nextToken"]
            more_objects = True
        else:
            break
    return records


def listAcctRoles(found_token, sso, sso_token, accountId):
    if found_token:
        roles_response = sso.list_account_roles(
            nextToken=found_token, accessToken=sso_token, accountId=accountId
        )
    else:
        roles_response = sso.list_account_roles(
            accessToken=sso_token, accountId=accountId
        )
    return roles_response


def ssoListAccountRoles(sso, sso_token, accountId):
    records = []
    more_objects = True
    found_token = ""
    while more_objects:
        accountRoles = listAcctRoles(found_token, sso, sso_token, accountId)
        for accountRole in accountRoles["roleList"]:
            if "roleName" in accountRole:
                records.append(accountRole["roleName"])

        # Now check there is more objects to list
        if "nextToken" in accountRoles:
            found_token = accountRoles["nextToken"]
            more_objects = True
        else:
            break
    return records


def list_regions(botocore_session):
    """List all regions."""
    return botocore_session.get_available_regions("ecr")


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


def aws_login(start_url, role_id, region):
    session = Session()
    sso_oidc = session.client("sso-oidc")
    client_creds = sso_oidc.register_client(
        clientName="ECR ",
        clientType="public",
    )
    device_authorization = sso_oidc.start_device_authorization(
        clientId=client_creds["clientId"],
        clientSecret=client_creds["clientSecret"],
        startUrl=start_url,
    )
    url = device_authorization["verificationUriComplete"]
    device_code = device_authorization["deviceCode"]
    expires_in = device_authorization["expiresIn"]
    interval = device_authorization["interval"]
    webbrowser.open(url, autoraise=True)
    for n in range(1, expires_in // interval + 1):
        sleep(interval)
        try:
            token = sso_oidc.create_token(
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode=device_code,
                clientId=client_creds["clientId"],
                clientSecret=client_creds["clientSecret"],
            )
            break
        except sso_oidc.exceptions.AuthorizationPendingException:
            pass
    sso = boto3.client("sso", region_name=region)
    sso_token = token.get("accessToken")
    listAccounts = ssoListAccounts(sso, sso_token)
    for accountId in listAccounts:
        listAcctRoles = ssoListAccountRoles(sso, sso_token, accountId)
        for roleId in listAcctRoles:
            if roleId == role_id:
                sts_credentials = sso.get_role_credentials(
                    accessToken=sso_token, accountId=accountId, roleName=roleId
                )

                aws_access_key_id = sts_credentials["roleCredentials"]["accessKeyId"]
                aws_secret_access_key = sts_credentials["roleCredentials"][
                    "secretAccessKey"
                ]
                aws_session_token = sts_credentials["roleCredentials"]["sessionToken"]

                # List ecr images with credentials
                region_list = list_regions(session)
                for region in region_list:
                    ecr = session.client(
                        service_name="ecr",
                        region_name=region,
                        aws_access_key_id=aws_access_key_id,
                        aws_secret_access_key=aws_secret_access_key,
                        aws_session_token=aws_session_token,
                    )
                    try:
                        response = ecr.get_authorization_token()

                        # get repository list
                        repositories = ecr.describe_repositories()

                        # get repository images
                        for repository in repositories["repositories"]:
                            images = ecr.describe_images(
                                repositoryName=repository["repositoryName"]
                            )
                            if len(images["imageDetails"]) > 0:
                                # formatted string to display account, repository name and size of an image
                                print(
                                    f"Account: {accountId} Repository: {repository['repositoryName']} Image size: {convert_size(images['imageDetails'][0]['imageSizeInBytes'])}"
                                )

                    except Exception as e:
                        pass


def main():
    print("AWS ECR Crawler v1.1")

    # Check for if arguments provided to the script
    if len(sys.argv) > 1:
        start_url = sys.argv[1]

        # if empty string provided for account_id and role_id, then use default values
        if len(sys.argv) >= 3:
            role_id = sys.argv[2]  # AWSAdministratorAccess
        else:
            role_id = "AWSAdministratorAccess"

        # if empty string provided for account_id and role_id, then use default values
        if len(sys.argv) >= 4:
            region = sys.argv[3]  # eu-west-1
        else:
            region = "eu-west-1"

        try:
            print(f"Start URL: {start_url} Role ID: {role_id} Region: {region}")
            aws_login(start_url, role_id, region)
        except Exception as e:
            print(f"Failed to login to AWS and run the aws crawler: {e}")
    else:
        print("Usage: python main.py <start_url> <role_id> <region>")


if __name__ == "__main__":
    main()
