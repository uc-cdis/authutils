from authutils.token.utils import get_projects_with_access
from authutils.token.utils import get_project_access
from authutils.token.utils import is_admin

EXAMPLE_ACCESS_TOKEN = {
  'sub': '7',
  'azp': 'test-client',
  'pur': 'access',
  'aud': [
    'openid',
    'user',
    'test-client'
  ],
  'context': {
    'user': {
      'is_admin': False,
      'name': 'test',
      'projects': {
        'phs000178': [
          'read',
          'update',
          'create',
          'delete',
          'read-storage'
        ],
        'phs000179': [
          'create',
        ],
        'phs000180': [
          'read',
          'read-storage'
        ]
      }
    }
  },
  'iss': 'https://bionimbus-pdc.opensciencedatacloud.org',
  'jti': '2e6ade06-5afb-4ce7-9ab5-e206225ce291',
  'exp': 1516983302,
  'iat': 1516982102
}


def test_get_projects_with_access():
    result = get_projects_with_access(EXAMPLE_ACCESS_TOKEN, 'read')
    assert len(result) == 2
    assert 'phs000178' in result
    assert 'phs000180' in result


def test_get_project_access():
    access_levels = get_project_access(EXAMPLE_ACCESS_TOKEN, 'phs000180')
    assert len(access_levels) == 2
    assert 'read' in access_levels
    assert 'read-storage' in access_levels


def test_is_admin_false():
    result = is_admin(EXAMPLE_ACCESS_TOKEN)
    assert not result


def test_is_admin_true():
    EXAMPLE_ACCESS_TOKEN['context']['user']['is_admin'] = True
    result = is_admin(EXAMPLE_ACCESS_TOKEN)
    assert result
