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
    <script src="https://code.jquery.com/jquery-3.5.1.js"></script>
    <script src="https://cdn.datatables.net/1.13.2/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.2/js/dataTables.bootstrap.min.js"></script>
    <link
      rel="stylesheet"
      type="text/css"
      href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"
    />
    <link
      rel="stylesheet"
      type="text/css"
      href="https://cdn.datatables.net/1.13.2/css/dataTables.bootstrap.min.css"
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
        --primary-color: #a366ff;
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
        max-width: 100%;
        overflow-x: hidden;
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
        background: var(--black-light-color);
        border-radius: 12px;
        transition: all 0.3s ease;
      }

      ::-webkit-scrollbar-thumb:hover {
        background: #3a3b3c;
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

      #progress-bar-container {
        width: 200px;
        height: 10px;
        background-color: #f0f0f0;
        border-radius: 5px;
        overflow: hidden;
      }

      #progress-bar {
          height: 100%;
          background-color: #2196f3;
          transition: width 0.5s ease-in-out;
      }

      .checkbox-group input[type="checkbox"] {
        display: inline-block;
        margin-right: 10px;
      }

      .select-form {
        background-color: #f4f4f4;
        border: none;
        border-radius: 4px;
        padding: 8px 16px;
        font-size: 16px;
        margin-bottom: 16px;
        width: 100%
      }

      .select-form option {
        font-size: 16px;
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
          <li>
            <a href="#">
              <i class="uil uil-files-landscapes"></i>
              <span class="link-name" id="aclBtn">ACL</span>
            </a>
          </li>
          <li>
            <a href="#">
              <i class="uil uil-files-landscapes"></i>
              <span class="link-name" id="dependencyBtn">Dependency Vulnerability</span>
            </a>
          </li>
        </ul>

        <ul class="logout-mode">
          <li>
            <a href="https://github.com/noobpk" target="_blank">
              <i class="uil uil-signout"></i>
              <span class="link-name">Author</span>
            </a>
          </li>
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
      <div id="progress-bar-container">
        <div id="progress-bar"></div>
      </div>
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
            <span class="text">Abnormal Request</span>
          </div>

          <table id="abnormal_request" class="table table-striped table-bordered" style="width: 100%">
            <thead>
              <tr>
                <th>IncidentID</th>
                <th>Time</th>
                <th>Request</th>
                <th>Type</th>
                <th>Predict</th>
              </tr>
            </thead>
            <tbody>
              {% for row in _gemini_data_store%}
              <tr>
                <td>{{ row['IncidentID'] }}</td>
                <td>{{ row['Time'] }}</td>
                <td>{{ row['Request'] }}</td>
                <td>{{ row['AttackType'] }}</td>
                <td>{{ row['Predict'] }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>

        <div class="activity">
          <div class="title">
            <i class="uil uil-clock-three"></i>
            <span class="text">Access List Control</span>
          </div>

          <table id="acl" class="table table-striped table-bordered" style="width: 100%">
            <thead>
              <tr>
                <th>Time</th>
                <th>Ip Address</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {% for acl in _gemini_acl %}
              <tr>
                <td style='text-align:center; vertical-align:middle'>{{ acl['Time'] }}</td>
                <td style='text-align:center; vertical-align:middle'>{{ acl['Ip'] }}</td>
                <td style='text-align:center; vertical-align:middle'><button class="remove-acl-btn" data-ip="{{ acl['Ip'] }}">Remove ACL</button></td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>

        <div class="activity">
          <div class="title">
            <i class="uil uil-clock-three"></i>
            <span class="text">Activity Log</span>
          </div>

          <table id="activity_log" class="table table-striped table-bordered" style="width: 100%">
            <thead>
              <tr>
                <th>Time</th>
                <th>Status</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {% for log in _gemini_log %}
              <tr>
                <td>{{ log.time }}</td>
                <td>{{ log.status }}</td>
                <td>{{ log.message }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
      <!-- The Config Modal -->
      <div id="configModal" class="modal">
        <!-- Modal Content -->
        <div class="modal-content">
          <div class="modal-header">
            <span class="close configClose">&times;</span>
            <h2>Configuration</h2>
          </div>
          <div class="modal-body">
            <form method="POST" action="{{url_for('gemini_update_config')}}">
              <div class="form-group">
                <label for="protect_mode">Global Protect Mode:</label>
                <div class="form-group">
                  <select class="select-form" name="protect_mode">
                    <option value="off" {% if _protect_mode == 'off' %}selected{% endif %}>Off</option>
                    <option value="monitor" {% if _protect_mode == 'monitor' %}selected{% endif %}>Monitor</option>
                    <option value="block" {% if _protect_mode == 'block' %}selected{% endif %}>Block</option>
                  </select>
                </div>
                <label for="safe_redirect_status">Safe Redirect:</label>
                <div class="form-group">
                  <select class="select-form" name="safe_redirect_status">
                    <option value="off" {% if _safe_redirect_status == 'off' %}selected{% endif %}>Off</option>
                    <option value="on" {% if _safe_redirect_status == 'on' %}selected{% endif %}>On</option>
                  </select>
                </div>
              </div>
              <label for="sensitive_value">Sensitive:</label>
              <div class="form-group">
                <input
                  type="text"
                  id="sensitive_value"
                  name="sensitive_value"
                  value="{{_sensitive_value}}"
                />
              </div>
              <label for="max_content_length">Max Content-Length: 1 * 1024 * 1024 = 1MB</label>
              <div class="form-group">
                <input
                  type="text"
                  id="max_content_length"
                  name="max_content_length"
                  value="{{_max_content_length}}"
                />
              </div>
              <label for="http_method_allow">HTTP Method Allow:</label>
              <div class="form-group checkbox-group">
                <label><input type="checkbox" name="http_method[]" value="OPTIONS" {{ 'checked' if 'OPTIONS' in _http_method else '' }}>OPTIONS</label>
                <label><input type="checkbox" name="http_method[]" value="GET" {{ 'checked' if 'GET' in _http_method else '' }}>GET</label>
                <label><input type="checkbox" name="http_method[]" value="POST" {{ 'checked' if 'POST' in _http_method else '' }}>POST</label>
                <label><input type="checkbox" name="http_method[]" value="PUT" {{ 'checked' if 'PUT' in _http_method else '' }}>PUT</label>
                <label><input type="checkbox" name="http_method[]" value="DELETE" {{ 'checked' if 'DELETE' in _http_method else '' }}>DELETE</label>
                <label><input type="checkbox" name="http_method[]" value="TRACE" {{ 'checked' if 'TRACE' in _http_method else '' }}>TRACE</label>
                <label><input type="checkbox" name="http_method[]" value="CONNECT" {{ 'checked' if 'CONNECT' in _http_method else '' }}>CONNECT</label>
              </div>
              <label for="trust_domain_list">Trust Domain:</label>
              <div class="form-group">
                <input
                  type="text"
                  id="trust_domain_list"
                  name="trust_domain_list"
                  value="{{_trust_domain_list}}"
                />
              </div>
              <button type="submit">Submit</button>
            </form>
          </div>
          <div class="modal-footer">
          </div>
        </div>
      </div>
      <!-- The ACL Modal -->
      <div id="aclModal" class="modal">
        <!-- Modal Content -->
        <div class="modal-content">
          <div class="modal-header">
            <span class="close aclClose">&times;</span>
            <h2>Access List Control</h2>
          </div>
          <div class="modal-body">
            <form method="POST" action="{{url_for('gemini_update_acl')}}">
              <label for="deney_ip">Deny IP:</label>
              <div class="form-group">
                <input
                  type="text"
                  id="ip_address"
                  name="ip_address"
                  placeholder="127.0.0.1"
                />
              </div>
              <button type="submit">Submit</button>
            </form>
          </div>
          <div class="modal-footer">
          </div>
        </div>
      </div>
      <!-- The Dependency Modal -->
      <div id="dependencyModal" class="modal">
        <!-- Modal Content -->
        <div class="modal-content">
          <div class="modal-header">
            <span class="close dependencyClose">&times;</span>
            <h2>Dependency Vulnerability</h2>
          </div>
          <div class="modal-body">
            <form method="POST" action="{{url_for('gemini_dependency_audit')}}">
              <label for="denpendencyPath">Path:</label>
              <div class="form-group">
                <select class="select-form" name="dependency_path" id="dependency_path">
                  {% for file in _gemini_dependency_file %}
                  <option value="{{file}}">{{file}}</option>
                  {% endfor %}
                </select>
              </div>
              <button type="submit">Check</button>
            </form>
            <!-- Box to display audit results -->
            <div class="audit-results">
              <h3>Audit Results:</h3>
              {% if _gemini_dependency_result %}
              <table id="dependency_result" class="table table-striped table-bordered" style="width: 100%">
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Package</th>
                    <th>Version</th>
                    <th>CVE ID</th>
                    <th>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {% for entry in _gemini_dependency_result['gemini_audit_dependency'] %}
                      {% for timestamp, details in entry.items() %}
                          {% for detail in details %}
                              <tr>
                                  <td>{{ timestamp }}</td>
                                  <td>{{ detail['package'] }}</td>
                                  <td>{{ detail['version'] }}</td>
                                  {% if detail['cve_id'] %}
                                  <td><a href="https://nvd.nist.gov/vuln/detail/{{ detail['cve_id'] }}">{{ detail['cve_id'] }}</a></td>
                                  {% else %}
                                  <td>Not found</td>
                                  {% endif %}
                                  <td>{{ detail['severity'] }}</td>
                              </tr>
                          {% endfor %}
                      {% endfor %}
                  {% endfor %}
              </tbody>
              </table>
              {% endif %}
            </div>
          </div>
          <div class="modal-footer">
            <i>Note: It takes some time to check. Please see the following results.</i>
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
        $("#activity_log").DataTable();
      });

      $(document).ready(function () {
        $("#abnormal_request").DataTable({
          lengthMenu: [
            [5, 10, 25, -1],
            [5, 10, 25, "All"],
          ],
          pageLength: 5,
        });
      });

      $(document).ready(function () {
        $("#acl").DataTable({
          lengthMenu: [
            [5, 10, 25, -1],
            [5, 10, 25, "All"],
          ],
          pageLength: 5,
        });
      });

      $(document).ready(function () {
        $("#dependency_result").DataTable({
          lengthMenu: [
            [5, 10, 25, -1],
            [5, 10, 25, "All"],
          ],
          pageLength: 5,
        });
      });

      // Get the modal
      var config_modal = document.getElementById("configModal");
      var acl_modal = document.getElementById("aclModal");
      var dependency_modal = document.getElementById("dependencyModal");

      // Get the button that opens the modal
      var config_btn = document.getElementById("configurationBtn");
      var acl_btn = document.getElementById("aclBtn");
      var dependency_btn = document.getElementById("dependencyBtn");

      // Get the <span> element that closes the modal
      var config_span = document.getElementsByClassName("configClose")[0];
      var acl_span = document.getElementsByClassName("aclClose")[0];
      var dependency_span = document.getElementsByClassName("dependencyClose")[0];

      // When the user clicks the button, open the modal
      config_btn.onclick = function () {
        config_modal.style.display = "block";
      };

      acl_btn.onclick = function () {
        acl_modal.style.display = "block";
      };

      dependency_btn.onclick = function () {
        dependency_modal.style.display = "block";
      };

      // When the user clicks on <span> (x), close the modal
      config_span.onclick = function () {
        config_modal.style.display = "none";
      };

      acl_span.onclick = function () {
        acl_modal.style.display = "none";
      };

      dependency_span.onclick = function () {
        dependency_modal.style.display = "none";
      };

      // When the user clicks anywhere outside of the modal, close it
      window.onclick = function (event) {
        if (event.target == config_modal) {
          config_modal.style.display = "none";
        }
        if (event.target == acl_modal) {
          acl_modal.style.display = "none";
        }
        if (event.target == dependency_modal) {
          dependency_modal.style.display = "none";
        }
      };

      $(document).ready(function() {
          // Set the initial progress to 0%
          var progress = 0;
          $("#progress-bar").css("width", progress + "%");

          // Calculate the increment value for the progress bar
          var increment = 100 / 30;

          // Start the progress update loop
          var interval = setInterval(function() {
              // Increment the progress by the increment value
              progress += increment;
              if (progress > 100) {
                  // Clear the interval and reload the page
                  clearInterval(interval);
                  $("#progress-bar").css("width", "100%");
                  setTimeout(function() {
                      location.reload();
                  }, 1000);
              } else {
                  // Update the progress bar width and color
                  $("#progress-bar").css("width", progress + "%");
                  if (progress < 50) {
                      $("#progress-bar").css("background-color", "#27ae60");
                  } else if (progress < 80) {
                      $("#progress-bar").css("background-color", "#f39c12");
                  } else {
                      $("#progress-bar").css("background-color", "#e74c3c");
                  }
              }
          }, 1000);
        });
        const removeButtons = document.querySelectorAll('.remove-acl-btn');
        removeButtons.forEach(button => {
          button.addEventListener('click', () => {
            const ip = button.getAttribute('data-ip');
            fetch('{{url_for('gemini_remove_acl')}}', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
              },
              body: `ip_address=${ip}`
            })
            .then(response => {
              if (!response.ok) {
                throw new Error('Network response was not ok');
              }
              return location.reload();
            })
            .catch(error => {
              console.error('There was a problem with the fetch operation:', error);
            });
          });
        });
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
            template_directory = os.path.join(
                flask_template_folder, r'gemini_protector_template')
            if not os.path.exists(template_directory):
                os.makedirs(template_directory)

            with open(flask_template_folder+'/gemini_protector_template/login.html', 'w+', encoding="utf-8") as f:
                f.write(template_login)

            with open(flask_template_folder+'/gemini_protector_template/dashboard.html', 'w+', encoding="utf-8") as f:
                f.write(template_dashboard)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def gemini_static_file(flask_static_folder):
        """
        It creates a directory called gemini_protector_static in the static folder of the flask app.

        :param flask_static_folder: This is the folder where you want to store the static files
        """
        try:
            static_directory = os.path.join(
                flask_static_folder, r'gemini_protector_static')
            if not os.path.exists(static_directory):
                os.makedirs(static_directory)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
