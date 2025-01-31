# Copyright The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

from flask import Flask, request
import time

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():

    # Enforce Python Flask Server to wait for the entire payload
    # rather than responding for request headers.
    print(request.get_json(force=True, silent=True, cache=False))

    time.sleep(2)

    return "Hello, World!"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8005, debug=True)
