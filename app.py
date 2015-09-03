from flask import Flask, request, Response, render_template, redirect
from subprocess import Popen, PIPE
import os, re, platform
app = Flask(__name__)

def mkdir(path):
    if not os.path.exists(path):
        os.makedirs(path, 0700)

messages_path = './messages'
mkdir(messages_path)

class GnuPG(object):
    def __init__(self):
        if platform.system() == 'Darwin':
            self.gpg_path = '/usr/local/bin/gpg'
        elif platform.system() == 'Linux':
            self.gpg_path = '/usr/bin/gpg'

        # Create a homedir to work in
        self.homedir = './homedir'
        mkdir(self.homedir)

        # Default key server
        self.keyserver = 'hkp://pool.sks-keyservers.net'

        # Base command to run
        self.gpg_command = [self.gpg_path, '--batch', '--no-tty', '--keyserver', self.keyserver, '--homedir', self.homedir]

    def is_gpg_available(self):
        return os.path.isfile(self.gpg_path)

    def verify(self, text):
        p = Popen(self.gpg_command + ['--verify'], stdout=PIPE, stdin=PIPE, stderr=PIPE)
        (stdoutdata, stderrdata) = p.communicate(text)
        print stderrdata

        # Do we have the signing key?
        if "Can't check signature: No public key" in stderrdata:
            keyid = ''
            for line in stderrdata.split('\n'):
                if line.startswith('gpg: Signature made'):
                    keyid = line.split()[-1]
            if re.match(r'^[a-fA-F\d]{8}$', keyid):
                # Try to fetch the signing key from key server
                p = Popen(self.gpg_command + ['--recv-keys', keyid], stdout=PIPE, stdin=PIPE, stderr=PIPE)
                p.wait()
                stderrdata = p.stderr.read()
                print stderrdata

                if "key {} not found on keyserver".format(keyid) in stderrdata:
                    return ("The signing key was not found on key servers", None)
                else:
                    import_success = False
                    for line in stderrdata.split('\n'):
                        if line.startswith('gpg: key {}: public key "'.format(keyid)) and line.endswith('" imported'):
                            import_success = True

                    if not import_success:
                        return ('Failed to import signing key from key server', None)

                    # Call verify again, now that we have the key
                    return self.verify(text)
            else:
                return ('No public key, and cannot extract keyid', None)

        # Was the signature good?
        good_sig = False
        fingerprint = None
        for line in stderrdata.split('\n'):
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

gpg = GnuPG()

@app.route('/')
def index():
    return render_template('index.html')

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

@app.route('/update', methods=['POST'])
def update():
    text = request.form['signed-text']

    # Check for valid-looking PGP-signed text
    if '-----BEGIN PGP SIGNED MESSAGE-----' not in text or '-----BEGIN PGP SIGNATURE-----' not in text or '-----END PGP SIGNATURE-----' not in text:
        return "That wasn't a PGP-signed message"

    # Verify the signature
    error, fp = gpg.verify(text)
    if error:
        return error

    # The signature is valid, so save it
    path = os.path.join(messages_path, fp)
    open(path, 'w').write(text)

    return redirect('/%s' % fp)

if __name__ == '__main__':
    app.run(debug=True)
