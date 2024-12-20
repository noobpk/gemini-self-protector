# gemini-self-protector

Gemini - The Runtime Application Self Protection (RASP) Solution Combined With Deep Learning

[![CodeQL](https://github.com/noobpk/gemini-self-protector/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/noobpk/gemini-self-protector/actions/workflows/codeql.yml)
[![trivy](https://github.com/noobpk/gemini-self-protector/actions/workflows/trivy.yml/badge.svg?branch=main)](https://github.com/noobpk/gemini-self-protector/actions/workflows/trivy.yml)
![Static Badge](https://img.shields.io/badge/python-3.x-blue?logo=python)
![Static Badge](https://img.shields.io/badge/Deep%20Learning-orange)
![Static Badge](https://img.shields.io/badge/Convolutional%20Neural%20Network-yellow)
![Static Badge](https://img.shields.io/badge/Recurrent%20Neural%20Network-%23ff6666)
![Static Badge](https://img.shields.io/badge/Sentence%20Transformers-%236e31ff)

## Introduction

Gemini-Self-Protector pioneers the fusion of Runtime Application Self Protection (RASP) and transformative Deep Learning. In today's evolving digital landscape, intelligent and adaptive application security is paramount. Enter Gemini-Self-Protector, ushering in a new era of proactive defense that revolutionizes application safeguarding amid ever-changing threats.

By seamlessly integrating RASP into your application's runtime fabric, Gemini-Self-Protector achieves unparalleled protection. It dynamically monitors and secures various aspects of functionality—database interactions, file operations, and network communications. This symbiosis with Deep Learning empowers Gemini-Self-Protector to adapt and evolve defenses in real-time, staying ahead of emerging threats.

## Gemini Components

![image](https://github.com/noobpk/gemini-web-vulnerability-detection/assets/31820707/4f38e403-b5f4-40a8-8823-def4353a813f)

👉 G-SP : [gemini-self-protector](https://github.com/noobpk/gemini-self-protector)

👉 G-WVD : [gemini-web-vulnerability-detection](https://github.com/noobpk/gemini-web-vulnerability-detection)

👉 G-BD : [gemini-bigdata](https://github.com/noobpk/gemini-bigdata)

## Gemini Plugin Architecture

The architecture of gemini-self-protector is composed of seven layers however it is optimized so as not to affect the performance on the application.

![image](https://user-images.githubusercontent.com/31820707/232506270-b0776d83-34b8-47fb-aa2a-eab3a4cc3be7.png)

## Language Support

| Language | Platform/ Framework |
| -------- | ------------------- |
| Python   | Flask               |

## Deep Learning Technology

Gemini uses a deep learning model that combines Convolutional Neural Network (CNN) and a family of Recurrent neural network (RNN) techniques to detect and identify vulnerabilities.

For more details: [G-WVD-DL](https://github.com/noobpk/gemini-web-vulnerability-detection/blob/main/DEEPLEARNING.md)

## More About Gemini-Self-Protector

📜 All about Gemini-Self-Protector is in [here](https://github.com/noobpk/gemini-self-protector/wiki)

## Installation

```
pip install gemini_self_protector
```

## Quick Start
⚙️ See detailed installation instructions [here](https://github.com/noobpk/gemini-self-protector/wiki/Quick-Start)

## Protect Mode & Sensitive

Gemini supports 3 modes and recommends sensitivity levels for the application to operate at its best state.

| Mode      | Sensitive |
| --------- | --------- |
| off       | N/A       |
| monitor   | 70        |
| protector | 50        |


## Implement G-WVD Serve
💪 You can implement your own G-WVD serve extremely simply and quickly. Details at [gemini-web-vulnerability-detection (G-WVD)](https://github.com/noobpk/gemini-web-vulnerability-detection)

## Demo

[Gemini-Self-Protector | Demo | Install - Configurate - Usage](https://youtu.be/sUJsJE29KcE)

## Screenshot

### New Dashboard Metrix 

![image](https://github.com/user-attachments/assets/d7733f82-fc81-42a2-99f6-b08d6f5255be)

### Dashboard

<img width="1440" alt="image" src="https://github.com/noobpk/gemini-self-protector/assets/31820707/068048ef-42cf-4032-b064-137d69abccb6">

### Monitoring

![image](https://github.com/noobpk/gemini-self-protector/assets/31820707/c4308492-c283-4c8c-a22f-8e503079b30e)

### Configurate

<img width="1440" alt="image" src="https://github.com/noobpk/gemini-self-protector/assets/31820707/d8e4376f-72d1-4a7d-8a96-838b9436b0b1">

### Access Control List

<img width="1440" alt="image" src="https://github.com/noobpk/gemini-self-protector/assets/31820707/496033ec-e953-4ca4-9d16-73a402161f8a">

### Dependency Check

![image](https://github.com/noobpk/gemini-self-protector/assets/31820707/e5b58af5-fe2a-4f3a-ab03-e25923bd72ee)

### Endpoint 

<img width="1440" alt="image" src="https://github.com/noobpk/gemini-self-protector/assets/31820707/109717d9-aac2-4c97-8e36-133e2d6365cb">

## Contributing

Interested in contributing? Check out the contributing guidelines. Please note that this project is released with a Code of Conduct. By contributing to this project, you agree to abide by its terms.

## License

`gemini_self_protector` was created by lethanhphuc. It is licensed under the terms of the MIT license.

## Theme

https://appseed.us/product/datta-able/flask/

## Research Publication

`Phuc Le-Thanh, Tuan Le-Anh, and Quan Le-Trung. 2023. Research and Development of a Smart Solution for Runtime Web Application Self-Protection. In Proceedings of the 12th International Symposium on Information and Communication Technology (SOICT '23). Association for Computing Machinery, New York, NY, USA, 304–311. https://doi.org/10.1145/3628797.3628901`
