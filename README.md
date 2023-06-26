# gemini-self-protector

Gemini - The Runtime Application Self Protection (RASP) Solution Combined With Deep Learning

[![CodeQL](https://github.com/noobpk/gemini-self-protector/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/noobpk/gemini-self-protector/actions/workflows/codeql.yml)
![Static Badge](https://img.shields.io/badge/python-3.x-blue?logo=python)
![Static Badge](https://img.shields.io/badge/Deep%20Learning-orange)
![Static Badge](https://img.shields.io/badge/Convolutional%20Neural%20Network-yellow)
![Static Badge](https://img.shields.io/badge/Recurrent%20neural%20network-%23ff6666)



## Architecture

The architecture of gemini-self-protector is composed of seven layers however it is optimized so as not to affect the performance on the application.

![image](https://user-images.githubusercontent.com/31820707/232506270-b0776d83-34b8-47fb-aa2a-eab3a4cc3be7.png)

## Support

| Language | Platform/ Framework |
| -------- | ------------------- |
| Python   | Flask               |

## Deep Learning

Gemini uses a deep learning model that combines Convolutional Neural Network (CNN) and a family of Recurrent neural network (RNN) techniques to detect and identify vulnerabilities.

For more details: [Web-Vuln-Detection-Predict](https://github.com/noobpk/Web-Vuln-Detection-Predict)

## Gemini Protect Against

| Attacks                 | Supported          |
| ----------------------- | ------------------ |
| Malformed Content Types |                    |
| HTTP Method Tampering   | :white_check_mark: |
| Large Requests          | :white_check_mark: |
| Path Traversal          |                    |
| Unvalidated Redirects   | :white_check_mark: |

| Injections                 | Supported          |
| -------------------------- | ------------------ |
| Command Injection          | :white_check_mark: |
| Cross-Site Scripting       | :white_check_mark: |
| Cross-Site Request Forgery |                    |
| CSS & HTML Injection       |                    |
| JSON & XML Injection       |                    |
| SQL Injection              | :white_check_mark: |

| Weaknesses                   | Supported          |
| ---------------------------- | ------------------ |
| Insecure Cookies & Transport |                    |
| Weak Browser Caching         | :white_check_mark: |
| Vulnerable Dependencies      | :white_check_mark: |
| Weak Cryptography            |                    |
| HTTP Response Headers        | :white_check_mark: |
| API Rate Limit               | :white_check_mark: |

## Gemini Security Response Headers

| HTTP Response Headers | Default configuration | 
| ------------------------------ | --------------------- |
| X-Frame-Options                | SAMEORIGIN            |
| X-XSS-Protection               | 1; mode=block         |
| X-Content-Type-Options         | nosniff               |
| Referrer-Policy                | no-referrer-when-downgrade |
| Content-Type                   | N/A                   |
| Strict-Transport-Security      | max-age=31536000; includeSubDomains; preload |
| Expect-CT                      | enforce; max-age=31536000 |
| Content-Security-Policy        | N/A                   |
| X-Permitted-Cross-Domain-Policies | none               |
| Feature-Policy                 | fullscreen 'self'     |
| Cache-Control                  | no-cache, no-store, must-revalidate |
| Pragma                         | no-cache              |
| Expires                        | 0                     |
| X-UA-Compatible                | IE=Edge,chrome=1      |
| Access-Control-Allow-Origin    | *                     |
| Access-Control-Allow-Methods   | *                     |
| Access-Control-Allow-Headers   | *                     |
| Access-Control-Allow-Credentials | true                |
| Cross-Origin-Opener-Policy     | N/A                   |
| Cross-Origin-Embedder-Policy   | N/A                   |
| Cross-Origin-Resource-Policy   | N/A                   |
| Permissions-Policy             | N/A                   |
| FLoC                           | N/A                   |
| Server                         | gemini                |
| X-Powered-By                   | N/A                   |
| X-AspNet-Version               | N/A                   |
| X-AspNetMvc-Version            | N/A                   |
| X-DNS-Prefetch-Control         | N/A                   |


## Installation

```
$ pip install gemini_self_protector
```

## Protect Mode & Sensitive

Gemini supports 3 modes and recommends sensitivity levels for the application to operate at its best state.

| Mode    | Sensitive |
| ------- | --------- |
| off     | N/A       |
| monitor | 70        |
| block   | 50        |

## Support Predict Server

| Address | Version |
| ------- | --------- |
| https://web-vuln-detect.my-app.in  | 19-06-2023  |

## License Key

The license key is used for authentication with the API.

Key: `988907ce-9803-11ed-a8fc-0242ac120002`

## GUI Features

👉 Monitor Abnormal Event

👉 Hot Configuration

👉 Access Control List

👉 Log Activity

👉 Dependency Vulnerability Check

## Theme
https://appseed.us/product/datta-able/flask/

## Contributing

Interested in contributing? Check out the contributing guidelines. Please note that this project is released with a Code of Conduct. By contributing to this project, you agree to abide by its terms.

## License

`gemini_self_protector` was created by lethanhphuc. It is licensed under the terms of the MIT license.

## ChangeLog
