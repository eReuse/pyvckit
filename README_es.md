# PyVckit
PyVckit es una librería para:
 - firmar credenciales verificables
 - verificar credenciales verificables
 - generar presentaciones verificables
 - verificar presentaciones verificables

Esta libreria esta fuertemente inspirada en [didkit de SpruceId](https://github.com/spruceid/didkit) y pretende mantener compatibilidad con ella.

Por ahora la criptografía soportada es solo EdDSA con una firma Ed25519Signature2018.

# Instalación
Por ahora la instalación es desde el repositorio:
```sh
    python -m venv env
    source env/bin/activate
    git clone https://gitea.pangea.org/ereuse/pyvckit.git
    cd pyvckit
    pip install -r requirements.txt
    pip install -e .
```

# Cli
El modo de uso bajo la linea de comandos seria el siguiente:

## generar un par de claves:
```sh
  python did.py -n keys > keypair.json
```

## generar un identificador did:
```sh
  python did.py -n did -k keypair.json
```

## generar una credencial firmada de ejemplo:
Se genera un ejemplo de credencial que es el que aparece en la plantilla credential_tmpl del fichero [templates.py](templates.py)
```sh
  python sign_vc.py -k keypair.json > credential_signed.json
```

## verificar una credencial firmada:
```sh
  python verify_vc.py credential_signed.json
```

## generar una presentación verificable:
```sh
  python sign_vp.py -k keypair.json -c credential_signed.json > presentation_signed.json
```

## verificat una presentación verificable:
```sh
  python verify_vp.py presentation_signed.json
```

# Uso como librería
En los test podras encontrar ejemplos de uso. Ahora explicare los casos habituales

## generar un par de claves:
```python
    from pyvckit.did import generate_keys
    key = generate_keys()
```

## generar un identificador did:
```python
    from pyvckit.did import generate_keys, generate_did
    key = generate_keys()
    did = generate_did(key)
```

## generar una credencial firmada:
Suponiendo que **credential** es una credencial válida.
**credential** es una variable de tipo string
```python
    from pyvckit.did import generate_keys, generate_did, get_signing_key
    from pyvckit.sign_vc import sign

    key = generate_keys()
    did = generate_did(key)
    signing_key = get_signing_key(key)
    vc = sign(credential, signing_key, did)
```

## verificar una credencial firmada:
Suponiendo que **vc** es una credencial verificable correctamente firmada
```python
    import json
    from pyvckit.verify import verify_vc

    verified = verify_vc(json.dumps(vc))
```

## generar una presentación verificable:
```python
    from pyvckit.did import generate_keys, generate_did, get_signing_key
    from pyvckit.sign_vp import sign_vp

    holder_key = generate_keys()
    holder_did = generate_did(holder_key)
    holder_signing_key = get_signing_key(holder_key)
    vp = sign_vp(holder_signing_key, holder_did, vc_string)
```

## verificat una presentación verificable:
```python
    from pyvckit.verify_vp import verify_vp
    verified = verify_vp(json.dumps(vp))
```
