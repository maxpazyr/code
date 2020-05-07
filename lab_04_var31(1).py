# py_ver == "3.6.9"
import flask


app = flask.Flask(__name__)


# root_ssh_pwd = "k33pc41mU$$Ri$c0min9"
# main_server_ip = "8.8.8.8"


@app.errorhandler(404)
def page_not_found(error):
    url = flask.request.path
    return """
          <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
          <title>404 Not Found</title>
          <h1>Not Found</h1>
          <p>The requested path <b>%s</b> was not found on the server.  If you entered the URL manually please check your spelling and try again.</p>
          """ % url


import os
from db import get_connection


def authenticate(name, password):
    sql_statement = "SELECT * " \
                    "FROM users " \
                    "WHERE name='{name}' "\
                    "AND password='{password}';".format(
                                                        name=name,
                                                        password=password,
                                                    )
    cursor = get_connection(
                            os.environ['DB_LOGIN'],
                            os.environ['DB_PASSWORD']
                            ).cursor()
    result = cursor.execute(sql_statement).fetchone()
    cursor.close()
    return result


@app.route('/login')
def index_page():
    return """
            <html>
                <title>Login page</title>
                <body>
                    <form action="/auth" method="post">
                        Login: <input name="name" type="text"/>
                        Password: <input name="password" type="password" />
                        <input name="submit" type="submit" value="Log in">
                        <input name="redirect_url" value="/?logged_in=1" type="hidden" />
                    </form>
                </body>
            </html>
        """


import hmac


@app.route('/auth', methods=["GET", "POST"])
def login_page():
    name = flask.request.form.get('name')
    password = flask.request.form.get('password')
    hmac.new(os.environ['SIGNATURE_KEY'].encode('utf8'),
             msg=flask.request.cookies.get('name').encode('utf8'),
             digestmod='sha256')
    already_auth = flask.request.cookies.get('ssid') == hmac.digest()
    just_auth = authenticate(name, password)
    if already_auth or just_auth:
        redirect_url = flask.request.args.get('redirect_url', '/')
        if redirect_url:
            response = flask.make_response(flask.redirect(redirect_url))
            if just_auth:
                response.set_cookie('ssid', hmac.digest())
            return response

        return """
            <html>
                <body>
                    Successfully logged in
                </body>
            </html>
        """

    return """
        <html>
            <body>
                Failed to authenticate
            </body>
        </html>
    """


@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Security-Policy'] = "default-src 'self'"
    return response


if __name__ == '__main__':
    app.run()
