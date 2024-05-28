# PyVckit
PyVckit es una librería para:
 - firmar credenciales verificables
 - verificar credenciales verificables
 - generar presentaciones verificables
 - verificar presentaciones verificables

Esta libreria esta fuertemente inspirada en (didkit de SpruceId)[https://github.com/spruceid/didkit/tree/main] y pretende mantener compatibilidad con ella.

Por ahora la criptografía soportada es solo EdDSA con una firma Ed25519Signature2018.

# Instalación
Por ahora la instalación es desde el repositorio:
```python
  python -m venv env
  source env/bin/activate
  git clone https://gitea.pangea.org/ereuse/pyvckit.git
  cd pyvckit
  pip install -r requirements.txt
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

## generar una credencial de ejemplo:
Se genera un ejemplo de credencial que es el que aparece en la plantilla credential_tmpl del fichero (template.py)[template.py]
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
