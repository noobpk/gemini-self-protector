import sys
import os

template_login = """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name=description content="Gemini Self-Protector">
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, user-scalable=no"
    />
    <meta name=owned content="lethanhphuc(noobpk)">
    <title>Gemini-self-protector login</title>
    <style>
      html,
      body,
      #root {
        height: 100%;
        width: 100%;
      }

      body {
        background: rgb(244, 247, 252);
        color: #111;
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
          Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji",
          "Segoe UI Symbol";
        overflow: hidden;
      }

      input,
      button {
        font-family: inherit;
        font-size: 1rem;
        line-height: 1rem;
      }

      .-button {
        background-color: rgb(87, 114, 245);
        border-radius: 5px;
        border: none;
        box-sizing: border-box;
        color: white;
        cursor: pointer;
        padding: 18px 20px;
        text-decoration: none;
      }

      .center-container {
        align-items: center;
        box-sizing: border-box;
        display: flex;
        flex-direction: column;
        justify-content: center;
        min-height: 100%;
        padding: 20px;
        width: 100%;
      }

      .card-box {
        background-color: rgb(250, 253, 258);
        border-radius: 5px;
        box-shadow: rgba(60, 66, 87, 0.117647) 0px 7px 14px 0px,
          rgba(0, 0, 0, 0.117647) 0px 3px 6px 0px;
        max-width: 650px;
        width: 100%;
      }

      .card-box > .header {
        border-bottom: 1px solid #ddd;
        color: #444;
        padding: 30px;
      }

      .card-box > .header > .main {
        margin: 0;
        font-size: 1.5rem;
      }

      .card-box > .header > .sub {
        color: #555;
        margin-top: 10px;
      }

      .card-box > .content {
        padding: 40px;
      }

      .card-box > .content > .none {
        margin: 2px 0;
      }

      .card-box + .card-box {
        margin-top: 26px;
      }

      canvas {
        top: 0;
        left: 0;
      }

      body {
        min-height: 568px;
        min-width: 320px;
        overflow: auto;
      }

      .login-form {
        display: flex;
        flex-direction: column;
        flex: 1;
        justify-content: center;
      }

      .login-form > .field {
        display: flex;
        flex-direction: row;
        width: 100%;
      }

      @media (max-width: 600px) {
        .login-form > .field {
          flex-direction: column;
        }
      }

      .login-form > .error {
        color: red;
        margin-top: 16px;
      }

      .login-form > .field > .password {
        background-color: rgb(244, 247, 252);
        border-radius: 5px;
        border: 1px solid #ddd;
        box-sizing: border-box;
        color: black;
        flex: 1;
        padding: 16px;
      }

      .login-form > .user {
        display: none;
      }

      .login-form > .field > .submit {
        margin-left: 20px;
      }

      @media (max-width: 600px) {
        .login-form > .field > .submit {
          margin-left: 0px;
          margin-top: 16px;
        }
      }

      input {
        -webkit-appearance: none;
      }
    </style>
  </head>
  <body>
    <div class="center-container">
      <div class="card-box">
        <div class="header">
          <h1 class="main">Welcome to Gemini-Self-Protector</h1>
          <div class="sub">
            Please log in below. Check the config file at
            gemini_protector/config.yaml for the password.
          </div>
          {% with messages = get_flashed_messages() %}
            {% if messages %}
              {% for message in messages %}
                <p class=info><strong>Message:</strong> {{ message }}
              {% endfor %}
            {% endif %}
          {% endwith %}

          {% if error %}
            <p class=error><strong>Message:</strong> {{ error }}
          {% endif %}
        </div>
        <div class="content">
          <form class="login-form" method="post">
            <div class="field">
              <input
                required
                autofocus
                class="password"
                type="password"
                placeholder="PASSWORD"
                name="password"
                autocomplete="current-password"
              />
              <input class="submit -button" value="SUBMIT" type="submit" />
            </div>
          </form>
        </div>
      </div>
    </div>
    <script>
      // Inform the backend about the path since the proxy might have rewritten
      // it out of the headers and cookies must be set with absolute paths.
      const el = document.getElementById("href");
      if (el) {
        el.value = location.href;
      }
    </script>
  </body>
</html>
"""
template_dashboard = """<!DOCTYPE html>
<html>
  <head>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js"></script>
    <link
      rel="stylesheet"
      type="text/css"
      href="https://cdn.datatables.net/1.10.21/css/jquery.dataTables.min.css"
    />
    <style>
      /* Add some styling to make the dashboard look nice */
      body {
        margin: 20px;
        overflow-y: scroll;
      }
      .container {
        display: flex;
        justify-content: space-between;
      }

      .card {
        width: 30%;
        padding: 20px;
        border: 1px solid gray;
        border-radius: 5px;
        text-align: center;
      }
    </style>
    <script>
      $(document).ready(function () {
        $("#example_table").DataTable({
          lengthMenu: [
            [5, 10, 25, -1],
            [5, 10, 25, "All"],
          ],
          pageLength: 5,
          columnDefs: [{ orderable: false, targets: [0, 2] }],
        });
      });
    </script>
  </head>
  <body>
    <h1>Gemini Self-Protector</h1>
    <div class="container">
      <div class="card">
        <h3>Users</h3>
        <p>Number of registered users: 100</p>
      </div>
      <div class="card">
        <h3>Orders</h3>
        <p>Number of completed orders: 50</p>
      </div>
      <div class="card">
        <h3>Revenue</h3>
        <p>Total revenue: $1000</p>
      </div>
    </div>
    <table id="example_table" class="display" style="width: 100%">
      <thead>
        <tr>
          <th>Column 1</th>
          <th>Column 2</th>
          <th>Column 3</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>Row 1 Column 1</td>
          <td>Row 1 Column 2</td>
          <td>Row 1 Column 3</td>
        </tr>
        <tr>
          <td>Row 2 Column 1</td>
          <td>Row 2 Column 2</td>
          <td>Row 2 Column 3</td>
        </tr>
        <tr>
          <td>Row 3 Column 1</td>
          <td>Row 3 Column 2</td>
          <td>Row 3 Column 3</td>
        </tr>
      </tbody>
    </table>
  </body>
</html>
"""

class _Template(object):

    def gemini_template(flask_template_folder):
        template_directory = os.path.join(flask_template_folder, r'gemini_protector_template')
        if not os.path.exists(template_directory):
            os.makedirs(template_directory)

        with open(flask_template_folder+'/gemini_protector_template/login.html','w+', encoding="utf-8") as f:
            f.write(template_login)

        with open(flask_template_folder+'/gemini_protector_template/dashboard.html','w+', encoding="utf-8") as f:
            f.write(template_dashboard)
  
    def gemini_static_file(flask_static_folder):
      static_directory = os.path.join(flask_static_folder, r'gemini_protector_static')
      if not os.path.exists(static_directory):
            os.makedirs(static_directory)

