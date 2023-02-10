import sys
import os
from ._logger import logger

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
      /* ===== Google Font Import - Poppins ===== */
      @import url("https://fonts.googleapis.com/css2?family=Poppins:wght@200;300;400;500;600&display=swap");
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
        font-family: "Poppins", sans-serif;
      }

      :root {
        /* ===== Colors ===== */
        --primary-color: #0e4bf1;
        --panel-color: #fff;
        --text-color: #000;
        --black-light-color: #707070;
        --border-color: #e6e5e5;
        --toggle-color: #ddd;
        --box1-color: #4da3ff;
        --box2-color: #ffe6ac;
        --box3-color: #e7d1fc;
        --title-icon-color: #fff;

        /* ====== Transition ====== */
        --tran-05: all 0.5s ease;
        --tran-03: all 0.3s ease;
        --tran-03: all 0.2s ease;
      }

      body {
        min-height: 100vh;
        background-color: var(--primary-color);
      }
      body.dark {
        --primary-color: #3a3b3c;
        --panel-color: #242526;
        --text-color: #ccc;
        --black-light-color: #ccc;
        --border-color: #4d4c4c;
        --toggle-color: #fff;
        --box1-color: #3a3b3c;
        --box2-color: #3a3b3c;
        --box3-color: #3a3b3c;
        --title-icon-color: #ccc;
      }
      /* === Custom Scroll Bar CSS === */
      ::-webkit-scrollbar {
        width: 8px;
      }
      ::-webkit-scrollbar-track {
        background: #f1f1f1;
      }
      ::-webkit-scrollbar-thumb {
        background: var(--primary-color);
        border-radius: 12px;
        transition: all 0.3s ease;
      }

      ::-webkit-scrollbar-thumb:hover {
        background: #0b3cc1;
      }

      body.dark::-webkit-scrollbar-thumb:hover,
      body.dark .activity-data::-webkit-scrollbar-thumb:hover {
        background: #3a3b3c;
      }

      nav {
        position: fixed;
        top: 0;
        left: 0;
        height: 100%;
        width: 250px;
        padding: 10px 14px;
        background-color: var(--panel-color);
        border-right: 1px solid var(--border-color);
        transition: var(--tran-05);
      }
      nav.close {
        width: 73px;
      }
      nav .logo-name {
        display: flex;
        align-items: center;
      }
      nav .logo-image {
        display: flex;
        justify-content: center;
        min-width: 45px;
      }
      nav .logo-image img {
        width: 40px;
        object-fit: cover;
        border-radius: 50%;
      }

      nav .logo-name .logo_name {
        font-size: 22px;
        font-weight: 600;
        color: var(--text-color);
        margin-left: 14px;
        transition: var(--tran-05);
      }
      nav.close .logo_name {
        opacity: 0;
        pointer-events: none;
      }
      nav .menu-items {
        margin-top: 40px;
        height: calc(100% - 90px);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
      }
      .menu-items li {
        list-style: none;
      }
      .menu-items li a {
        display: flex;
        align-items: center;
        height: 50px;
        text-decoration: none;
        position: relative;
      }
      .nav-links li a:hover:before {
        content: "";
        position: absolute;
        left: -7px;
        height: 5px;
        width: 5px;
        border-radius: 50%;
        background-color: var(--primary-color);
      }
      body.dark li a:hover:before {
        background-color: var(--text-color);
      }
      .menu-items li a i {
        font-size: 24px;
        min-width: 45px;
        height: 100%;
        display: flex;
        align-items: center;
        justify-content: center;
        color: var(--black-light-color);
      }
      .menu-items li a .link-name {
        font-size: 18px;
        font-weight: 400;
        color: var(--black-light-color);
        transition: var(--tran-05);
      }
      nav.close li a .link-name {
        opacity: 0;
        pointer-events: none;
      }
      .nav-links li a:hover i,
      .nav-links li a:hover .link-name {
        color: var(--primary-color);
      }
      body.dark .nav-links li a:hover i,
      body.dark .nav-links li a:hover .link-name {
        color: var(--text-color);
      }
      .menu-items .logout-mode {
        padding-top: 10px;
        border-top: 1px solid var(--border-color);
      }
      .menu-items .mode {
        display: flex;
        align-items: center;
        white-space: nowrap;
      }
      .menu-items .mode-toggle {
        position: absolute;
        right: 14px;
        height: 50px;
        min-width: 45px;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
      }
      .mode-toggle .switch {
        position: relative;
        display: inline-block;
        height: 22px;
        width: 40px;
        border-radius: 25px;
        background-color: var(--toggle-color);
      }
      .switch:before {
        content: "";
        position: absolute;
        left: 5px;
        top: 50%;
        transform: translateY(-50%);
        height: 15px;
        width: 15px;
        background-color: var(--panel-color);
        border-radius: 50%;
        transition: var(--tran-03);
      }
      body.dark .switch:before {
        left: 20px;
      }

      .dashboard {
        position: relative;
        left: 250px;
        background-color: var(--panel-color);
        min-height: 100vh;
        width: calc(100% - 250px);
        padding: 10px 14px;
        transition: var(--tran-05);
      }
      nav.close ~ .dashboard {
        left: 73px;
        width: calc(100% - 73px);
      }
      .dashboard .top {
        position: fixed;
        top: 0;
        left: 250px;
        display: flex;
        width: calc(100% - 250px);
        justify-content: space-between;
        align-items: center;
        padding: 10px 14px;
        background-color: var(--panel-color);
        transition: var(--tran-05);
        z-index: 10;
      }
      nav.close ~ .dashboard .top {
        left: 73px;
        width: calc(100% - 73px);
      }
      .dashboard .top .sidebar-toggle {
        font-size: 26px;
        color: var(--text-color);
        cursor: pointer;
      }
      .dashboard .top .search-box {
        position: relative;
        height: 45px;
        max-width: 600px;
        width: 100%;
        margin: 0 30px;
      }
      .top .search-box input {
        position: absolute;
        border: 1px solid var(--border-color);
        background-color: var(--panel-color);
        padding: 0 25px 0 50px;
        border-radius: 5px;
        height: 100%;
        width: 100%;
        color: var(--text-color);
        font-size: 15px;
        font-weight: 400;
        outline: none;
      }
      .top .search-box i {
        position: absolute;
        left: 15px;
        font-size: 22px;
        z-index: 10;
        top: 50%;
        transform: translateY(-50%);
        color: var(--black-light-color);
      }
      .top img {
        width: 40px;
        border-radius: 50%;
      }
      .dashboard .dash-content {
        padding-top: 0px;
      }
      .dash-content .title {
        display: flex;
        align-items: center;
        margin: 60px 0 30px 0;
      }
      .dash-content .title i {
        position: relative;
        height: 35px;
        width: 35px;
        background-color: var(--primary-color);
        border-radius: 6px;
        color: var(--title-icon-color);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 24px;
      }
      .dash-content .title .text {
        font-size: 24px;
        font-weight: 500;
        color: var(--text-color);
        margin-left: 10px;
      }
      .dash-content .boxes {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
      }
      .dash-content .boxes .box {
        display: flex;
        flex-direction: column;
        align-items: center;
        border-radius: 12px;
        width: calc(100% / 3 - 15px);
        padding: 15px 20px;
        background-color: var(--box1-color);
        transition: var(--tran-05);
      }
      .boxes .box i {
        font-size: 35px;
        color: var(--text-color);
      }
      .boxes .box .text {
        white-space: nowrap;
        font-size: 18px;
        font-weight: 500;
        color: var(--text-color);
      }
      .boxes .box .number {
        font-size: 40px;
        font-weight: 500;
        color: var(--text-color);
      }
      .boxes .box.box2 {
        background-color: var(--box2-color);
      }
      .boxes .box.box3 {
        background-color: var(--box3-color);
      }
      .dash-content .activity .activity-data {
        display: flex;
        justify-content: space-between;
        align-items: center;
        width: 100%;
      }
      .activity .activity-data {
        display: flex;
      }
      .activity-data .data {
        display: flex;
        flex-direction: column;
        margin: 0 15px;
      }
      .activity-data .data-title {
        font-size: 20px;
        font-weight: 500;
        color: var(--text-color);
      }
      .activity-data .data .data-list {
        font-size: 18px;
        font-weight: 400;
        margin-top: 20px;
        white-space: nowrap;
        color: var(--text-color);
      }

      @media (max-width: 1000px) {
        nav {
          width: 73px;
        }
        nav.close {
          width: 250px;
        }
        nav .logo_name {
          opacity: 0;
          pointer-events: none;
        }
        nav.close .logo_name {
          opacity: 1;
          pointer-events: auto;
        }
        nav li a .link-name {
          opacity: 0;
          pointer-events: none;
        }
        nav.close li a .link-name {
          opacity: 1;
          pointer-events: auto;
        }
        nav ~ .dashboard {
          left: 73px;
          width: calc(100% - 73px);
        }
        nav.close ~ .dashboard {
          left: 250px;
          width: calc(100% - 250px);
        }
        nav ~ .dashboard .top {
          left: 73px;
          width: calc(100% - 73px);
        }
        nav.close ~ .dashboard .top {
          left: 250px;
          width: calc(100% - 250px);
        }
        .activity .activity-data {
          overflow-x: scroll;
        }
      }

      @media (max-width: 780px) {
        .dash-content .boxes .box {
          width: calc(100% / 2 - 15px);
          margin-top: 15px;
        }
      }
      @media (max-width: 560px) {
        .dash-content .boxes .box {
          width: 100%;
        }
      }
      @media (max-width: 400px) {
        nav {
          width: 0px;
        }
        nav.close {
          width: 73px;
        }
        nav .logo_name {
          opacity: 0;
          pointer-events: none;
        }
        nav.close .logo_name {
          opacity: 0;
          pointer-events: none;
        }
        nav li a .link-name {
          opacity: 0;
          pointer-events: none;
        }
        nav.close li a .link-name {
          opacity: 0;
          pointer-events: none;
        }
        nav ~ .dashboard {
          left: 0;
          width: 100%;
        }
        nav.close ~ .dashboard {
          left: 73px;
          width: calc(100% - 73px);
        }
        nav ~ .dashboard .top {
          left: 0;
          width: 100%;
        }
        nav.close ~ .dashboard .top {
          left: 0;
          width: 100%;
        }
      }
      /* The Modal (background) */
      .modal {
        display: none; /* Hidden by default */
        position: fixed; /* Stay in place */
        z-index: 1; /* Sit on top */
        left: 0;
        top: 0;
        width: 100%; /* Full width */
        height: 100%; /* Full height */
        overflow: auto; /* Enable scroll if needed */
        background-color: rgb(0, 0, 0); /* Fallback color */
        background-color: rgba(0, 0, 0, 0.4); /* Black w/ opacity */
      }

      .modal-header {
        padding-bottom: 20px;
      }

      /* Modal Content/Box */
      .modal-content {
        background-color: #fefefe;
        margin: 15% auto; /* 15% from the top and centered */
        padding: 20px;
        border: 1px solid #888;
        width: 60%; /* Could be more or less, depending on screen size */
      }

      /* The Close Button */
      .close {
        color: #aaa;
        float: right;
        font-size: 28px;
        font-weight: bold;
      }

      .close:hover,
      .close:focus {
        color: black;
        text-decoration: none;
        cursor: pointer;
      }

      input[type="text"] {
        width: 100%;
        padding: 12px 20px;
        margin: 8px 0;
        box-sizing: border-box;
        border: 2px solid #ccc;
        border-radius: 4px;
      }

      input[type="text"]:focus {
        border: 2px solid #555;
      }

      button {
        background-color: #4caf50;
        color: white;
        padding: 12px 20px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 16px;
        margin: 10px;
      }

      button:hover {
        background-color: #3e8e41;
      }
    </style>
  </head>
  <body>
    <nav>
      <div class="logo-name">
        <div class="logo-image">
          <!--<img src="images/logo.png" alt="">-->
        </div>

        <span class="logo_name">Gemini Self-Protector</span>
      </div>

      <div class="menu-items">
        <ul class="nav-links">
          <li>
            <a href="#">
              <i class="uil uil-estate"></i>
              <span class="link-name">Dahsboard</span>
            </a>
          </li>
          <li>
            <a href="#">
              <i class="uil uil-files-landscapes"></i>
              <span class="link-name" id="configurationBtn">Configuration</span>
            </a>
          </li>
        </ul>

        <ul class="logout-mode">
          <li>
            <a href="{{url_for('gemini_logout')}}">
              <i class="uil uil-signout"></i>
              <span class="link-name">Logout</span>
            </a>
          </li>

          <li class="mode">
            <a href="#">
              <i class="uil uil-moon"></i>
              <span class="link-name">Dark Mode</span>
            </a>

            <div class="mode-toggle">
              <span class="switch"></span>
            </div>
          </li>
        </ul>
      </div>
    </nav>

    <section class="dashboard">
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          {% for message in messages %}
            <p class=info><strong>Message:</strong> {{ message }}
          {% endfor %}
        {% endif %}
      {% endwith %}
      <div class="dash-content">
        <div class="overview">
          <div class="title">
            <i class="uil uil-tachometer-fast-alt"></i>
            <span class="text">Dashboard</span>
          </div>

          <div class="boxes">
            <div class="box box1">
              <i class="uil uil-thumbs-up"></i>
              <span class="text">Global Protect Mode</span>
              <span class="number">{{_protect_mode}}</span>
            </div>
            <div class="box box2">
              <i class="uil uil-thumbs-up"></i>
              <span class="text">Normal Request</span>
              <span class="number">{{_normal_request}}</span>
            </div>
            <div class="box box3">
              <i class="uil uil-thumbs-up"></i>
              <span class="text">Abnormal Request</span>
              <span class="number">{{_abnormal_request}}</span>
            </div>
          </div>
        </div>

        <div class="activity">
          <div class="title">
            <i class="uil uil-clock-three"></i>
            <span class="text">Recent Activity</span>
          </div>

          <table id="example_table" class="display" style="width: 100%">
            <thead>
              <tr>
                <th>Time</th>
                <th>Status</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Row 1 Column 1</td>
                <td>Row 1 Column 2</td>
                <td>Row 1 Column 3</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <!-- The Modal -->
      <div id="myModal" class="modal">
        <!-- Modal Content -->
        <div class="modal-content">
          <div class="modal-header">
            <span class="close">&times;</span>
            <h2>Configuration</h2>
          </div>
          <div class="modal-body">
            <form method="POST" action="{{url_for('gemini_update_config')}}">
              <label for="username">Global Protect Mode:</label>
              <div class="form-group">
                <input
                  type="text"
                  id="protect_mode"
                  name="protect_mode"
                  value="{{_protect_mode}}"
                />
              </div>
              <label for="username">Sensitive:</label>
              <div class="form-group">
                <input
                  type="text"
                  id="sensitive_value"
                  name="sensitive_value"
                  value="{{_sensitive_value}}"
                />
              </div>
              <button type="submit">Submit</button>
            </form>
          </div>
          <div class="modal-footer">
            <p>Note: This is just a sample configuration popup.</p>
          </div>
        </div>
      </div>
    </section>

    <script>
      const body = document.querySelector("body"),
        modeToggle = body.querySelector(".mode-toggle");
      sidebar = body.querySelector("nav");
      sidebarToggle = body.querySelector(".sidebar-toggle");

      let getMode = localStorage.getItem("mode");
      if (getMode && getMode === "dark") {
        body.classList.toggle("dark");
      }

      let getStatus = localStorage.getItem("status");
      if (getStatus && getStatus === "close") {
        sidebar.classList.toggle("close");
      }

      modeToggle.addEventListener("click", () => {
        body.classList.toggle("dark");
        if (body.classList.contains("dark")) {
          localStorage.setItem("mode", "dark");
        } else {
          localStorage.setItem("mode", "light");
        }
      });

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

      // Get the modal
      var modal = document.getElementById("myModal");

      // Get the button that opens the modal
      var btn = document.getElementById("configurationBtn");

      // Get the <span> element that closes the modal
      var span = document.getElementsByClassName("close")[0];

      // When the user clicks the button, open the modal
      btn.onclick = function () {
        modal.style.display = "block";
      };

      // When the user clicks on <span> (x), close the modal
      span.onclick = function () {
        modal.style.display = "none";
      };

      // When the user clicks anywhere outside of the modal, close it
      window.onclick = function (event) {
        if (event.target == modal) {
          modal.style.display = "none";
        }
      };
    </script>
  </body>
</html>
"""

class _Template(object):

    def gemini_template(flask_template_folder):
      """
      It creates a folder called gemini_protector_template in the flask_template_folder and creates
      two files in it called login.html and dashboard.html
      
      :param flask_template_folder: This is the folder where you want to store the templates
      """
      try:
        template_directory = os.path.join(flask_template_folder, r'gemini_protector_template')
        if not os.path.exists(template_directory):
            os.makedirs(template_directory)

        with open(flask_template_folder+'/gemini_protector_template/login.html','w+', encoding="utf-8") as f:
            f.write(template_login)

        with open(flask_template_folder+'/gemini_protector_template/dashboard.html','w+', encoding="utf-8") as f:
            f.write(template_dashboard)
      except Exception as e:
        logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def gemini_static_file(flask_static_folder):
      """
      It creates a directory called gemini_protector_static in the static folder of the flask app.
      
      :param flask_static_folder: This is the folder where you want to store the static files
      """
      try:
        static_directory = os.path.join(flask_static_folder, r'gemini_protector_static')
        if not os.path.exists(static_directory):
              os.makedirs(static_directory)
      except Exception as e:
        logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))        

