"""
Utility functions for retrieving information from validated token
"""

def get_project_access(validated_token, project_name):
    """
    Return a list of access levels for the given project projects within the
    token.

    Args:
        validated_token (dict): dictionary of claims from a JWT
        access_level (str): requested access level (such as "read", "delete", etc)

    Returns:
        List(str): A list of project names in the token that have the given
                   access level
    """
    return validated_token["context"]["user"]["projects"].get(project_name, [])


def get_projects_with_access(validated_token, access_level):
    """
    Return a list of projects with the provided access level for the given
    token.

    Args:
        validated_token (dict): dictionary of claims from a JWT
        access_level (str): requested access level (such as "read", "delete", etc)

    Returns:
        List(str): A list of project names in the token that have the given
                   access level
    """
    return [
        project
        for project, allowed_access
        in validated_token["context"]["user"]["projects"].items()
        if access_level in allowed_access
    ]


def is_admin(validated_token):
    return validated_token["context"]["user"]["is_admin"]

def get_username(validated_token):
    return validated_token["context"]["user"]["name"]