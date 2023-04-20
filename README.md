# gemini-self-protector

Gemini - The Runtime Application Self Protection (RASP) Solution Combined With Deep Learning

[![CodeQL](https://github.com/noobpk/gemini-self-protector/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/noobpk/gemini-self-protector/actions/workflows/codeql.yml)

## Architecture

The architecture of gemini-self-protector is composed of seven layers however it is optimized so as not to affect the performance on the application.

![image](https://user-images.githubusercontent.com/31820707/232506270-b0776d83-34b8-47fb-aa2a-eab3a4cc3be7.png)

## Support

| Language | Platform/ Framework |
| -------- | ------------------- |
| Python   | Flask               |

## Deep Learning

Gemini uses a deep learning model that combines Convolutional Neural Network (CNN) and Long short-term memory (LSTM) to detect and identify vulnerabilities. This model uses convolution operation to determine the feature attributes and internal relationships in the input data thereby improving the accuracy of vulnerability detection.

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
| Command Injection          |                    |
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

## License Key

The license key is used for authentication with the API.
| | |
| ------- | --------- |
|Key|988907ce-9803-11ed-a8fc-0242ac120002|

## Dashboard Features

👉 Hot Configuration config.yml

👉 Access List Control

👉 Log Activity

👉 Dependency Vulnerability Check

👉 Monitor Abnormal Request

## Contributing

Interested in contributing? Check out the contributing guidelines. Please note that this project is released with a Code of Conduct. By contributing to this project, you agree to abide by its terms.

## ChangeLog
