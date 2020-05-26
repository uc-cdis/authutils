# authutils

Utilities for auth to work with sheepdog


## Install

```bash
$ pip install authutils
```

or

```bash
$ poetry add authutils
```


### Flask Support

```bash
$ pip install authutils[flask]
```

or

```bash
$ poetry add authutils -E flask
```

This provides:

* `authutils.user`
* `authutils.oauth2.client.authorize`
* `authutils.oauth2.client.blueprint`
* `authutils.token.keys`
* `authutils.token.validate`


### FastAPI Support

```bash
$ pip install authutils[fastapi]
```

or

```bash
$ poetry add authutils -E fastapi
```

This provides:

* `authutils.token.fastapi`
