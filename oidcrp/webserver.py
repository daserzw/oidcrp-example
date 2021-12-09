from flask import redirect, render_template, session, request
from oidcrp import app, client

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/authenticate')
def authenticate():
    redirect_url = client.authenticate(session)
    return redirect(redirect_url)

@app.route('/repost_fragment', methods=['POST'])
def repost_fragment(**kwargs):
    info = client.implicit_flow_callback(request.form['url_fragment'], session)
    return success_page(info)

@app.route('/code_flow_callback')
def code_flow_callback():
    if 'error' in request.form:
        return "{}: {}".format(request.form['error'], request.form['error_description']), 500
    info = client.code_flow_callback(request.query_string, session)
    return success_page(info)

@app.route('/implicit_flow_callback')
def implicit_flow_callback():
    return render_template('repost_fragment.html')

def success_page(info):
    return render_template(
        'success_page.html',
        client_id=info['client_id'],
        client_secret=info['client_secret'],
        auth_code=info['auth_code'],
        access_token=info['access_token'],
        id_token_claims=info['id_token_claims'],
        userinfo=info['userinfo']
    )
