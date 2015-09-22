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

    # Flask-Session
    # Docs: https://pythonhosted.org/Flask-Session/
    SESSION_COOKIE_HTTPONLY = True
    # TODO: This needs to be False for testing on localhost, but it
    # should probably be True in production if you are hosting with
    # HTTPS.
    SESSION_COOKIE_SECURE = False
    # Using the filesystem is in keeping with the use of a filesystem
    # as a database for the pastes, and avoids the need for
    # heavyweight dependencies.
    # TODO: This should probably be changed if you want to scale!
    SESSION_TYPE = 'filesystem'
    # Flask-Session changes the default for "permanent" sessions to
    # True. For this application, it's probably best to use
    # non-permanent cookies, which will automatically be erased on
    # closing your browser, since the values in the cookie are only
    # needed in the two-step authentication flow.
    SESSION_PERMANENT = False
    # Now that we're using server side sessions, there's less need to
    # use signed sessions. Since the session IDs are UUIDs, it's
    # highly unlikely that an attacker would be able to exploit their
    # ability to modify the session cookie's value by correctly
    # guessing another user's session ID. Nonetheless, it doesn't cost
    # much and so it seems like a sensible defense-in-depth measure.
    SESSION_USE_SIGNER = True
    # TODO: I'm leaving this set to the default of 500 for now, but
    # this should be considered as a potential DoS vector. Example
    # scenario:
    #
    # 1. Alice wants to post something to Sigbin. She starts by
    #    posting a valid signed message, and receives the
    #    authentication challenge.
    #
    # 2. Bob repeatedly and rapidly attempts to post something to
    #    sigbin, triggering the creation of a new session each time.
    #
    # 3. If Bob can trigger the creation of > SESSION_FILE_THRESHOLD
    #    new sessions before Alice has finished responding to the
    #    authentication challenge, her session will be erased from the
    #    session store and thus invalidated. Once she submits her
    #    response to the challenge, it will incorrectly fail and she
    #    will be unable to update the entry corresponding to her key.
    #
    # This DoS vector allows an attacker to block valid updates to
    # Sigbin, which is a serious problem in the context of some of
    # Sigbin's use cases (e.g. sharing key transition statements).
    #
    # Potential solutions are TODO but include raising this threshold
    # and/or rate limiting requests that create new sessions.
    SESSION_FILE_THRESHOLD = 500
