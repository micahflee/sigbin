from flask import Flask, session, request, Response, render_template, redirect, flash, get_flashed_messages
from subprocess import Popen, PIPE
import os, sys, re, platform, inspect

import config

app = Flask(__name__)
app.config.from_object(config.FlaskConfig)

d = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
def mkdir(path):
    if not os.path.exists(path):
        os.makedirs(path, 0700)

messages_path = os.path.join(d, 'message')
mkdir(messages_path)

class GnuPG(object):
    def __init__(self):
        if platform.system() == 'Darwin':
            self.gpg_path = '/usr/local/bin/gpg'
        elif platform.system() == 'Linux':
            self.gpg_path = '/usr/bin/gpg'

        # Create a homedir to work in
        self.homedir = os.path.join(d, 'homedir')
        mkdir(self.homedir)

        # Default key server
        self.keyserver = 'hkp://pool.sks-keyservers.net'

    def _gpg(self, args, input=None):
        p = Popen([self.gpg_path, '--batch', '--no-tty', '--keyserver', self.keyserver, '--homedir', self.homedir] + args, stdout=PIPE, stdin=PIPE, stderr=PIPE)
        if input:
            (out, err) = p.communicate(input)
        else:
            p.wait()
            out = p.stdout.read()
            err = p.stderr.read()

        if out != '':
            print 'stdout', out
        if err != '':
            print 'stderr', err
        return out, err

    def verify(self, message):
        out, err = self._gpg(['--verify'], message)

        # Do we have the signing key?
        if "Can't check signature: No public key" in err or "Can't check signature: public key not found" in err:
            keyid = ''
            for line in err.split('\n'):
                if line.startswith('gpg: Signature made'):
                    keyid = line.split()[-1]
            if re.match(r'^[a-fA-F\d]{8}$', keyid):
                # Try to fetch the signing key from key server
                out, err = self._gpg(['--recv-keys', keyid])

                if "key {} not found on keyserver".format(keyid) in err:
                    return ("The signing key was not found on key servers", None)
                else:
                    import_success = False
                    for line in err.split('\n'):
                        if line.startswith('gpg: key {}: public key "'.format(keyid)) and line.endswith('" imported'):
                            import_success = True

                    if not import_success:
                        return ('Failed to import signing key from key server', None)

                    # Call verify again, now that we have the key
                    return self.verify(message)
            else:
                return ('No public key, and cannot extract keyid', None)

        # Was the signature good?
        good_sig = False
        fingerprint = None
        for line in err.split('\n'):
            if line.startswith('gpg: Good signature from '):
                good_sig = True
            if line.startswith('Primary key fingerprint: '):
                fingerprint = line.lstrip('Primary key fingerprint: ').replace(' ', '').lower()

        if good_sig:
            if not fingerprint:
                return ('Good signature, but failed to extract the signing key\'s fingerprint', None)
            return (None, fingerprint)
        else:
            return ('Bad signature', None)

    def encrypt(self, message, fingerprint):
        out, err = self._gpg(['--armor', '--no-emit-version', '--no-comments', '--trust-model', 'always', '--encrypt', '--recipient', fingerprint], message)
        return out

gpg = GnuPG()

@app.route('/')
def index():
    return render_template('update1.html', site_name = config.SITE_NAME, homepage_text = config.HOMEPAGE_TEXT, footer = config.FOOTER)

@app.route('/<fingerprint>')
def view(fingerprint):
    fp = fingerprint.lower()

    # Check for valid-looking PGP fingerprint
    if re.match(r'^[a-fA-F\d]{40}$', fp):
        path = os.path.join(messages_path, fp)
        if os.path.isfile(path):
            return Response(open(path).read(), mimetype='text/plain')

        else:
            return 'Message not found'

    else:
        return 'Invalid fingerprint'

@app.route('/update/1', methods=['POST'])
def update1():
    message = request.form['signed-text']

    # Check for valid-looking PGP-signed text
    if '-----BEGIN PGP SIGNED MESSAGE-----' not in message or '-----BEGIN PGP SIGNATURE-----' not in message or '-----END PGP SIGNATURE-----' not in message:
        flash("That wasn't a PGP-signed message", 'error')
        return redirect('/')

    # Verify the signature
    error, fp = gpg.verify(message)
    if error:
        flash(error, 'error')
        return redirect('/')

    # The signature is valid, so save it in the session
    session['fp'] = fp
    session['message'] = message

    # Generate a challenge string, store it in the session
    session['challenge'] = open('/dev/urandom').read(16).encode('hex')

    # Encrypt it to the user's public key
    ciphertext = gpg.encrypt(session['challenge']+'\n', fp)

    # Challenge the user
    return render_template('update2.html', ciphertext = ciphertext, site_name = config.SITE_NAME, footer = config.FOOTER)

@app.route('/update/2', methods=['POST'])
def update2():
    challenge = request.form['challenge'].strip()
    if challenge == session['challenge']:
        # Success, save the message
        open(os.path.join(messages_path, session['fp']), 'w').write(session['message'])
        return redirect('/%s' % session['fp'])
    else:
        flash('Nice try but WRONG', 'error')
        return redirect('/')

if __name__ == '__main__':
    app.run()
