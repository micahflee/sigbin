SITE_NAME = 'Sigbin'
HOMEPAGE_TEXT = "Paste a PGP-signed message to save it. Pasting a new message signed with the same key will overwrite the old one."
FOOTER = 'Powered by Sigbin. Fork on <a href="#">GitHub</a>.'

class FlaskConfig(object):
    """
    Configuration for the Flask app and any extensions. Separated into
    an object to avoid namespace collisions.
    """
    DEBUG = False
    SECRET_KEY = 'put some random data here'
