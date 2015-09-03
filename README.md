# Sigbin

Sigbin is a web app that lets users store PGP-signed messages. Users paste a signed message into the box. If the signing key is on a key server and the signature is valid, it stores the signed message at `/[signing_key_fingerprint]`. If a message is already there, it overwrites it.

Getting started:

```sh
$ virtualenv env
$ . env/bin/activate
(env) $ pip install -r requirements.txt
(env) $ ./app.py
# when you're done
(env) $ deactivate
```
