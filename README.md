SOAR Engine

A Python-based SOAR (Security Orchestration, Automation, and Response) Engine for automating security operations, incident response, and threat intelligence workflows. Designed to integrate with multiple tools, including Slack notifications, AI-driven decision engines, and custom threat intelligence modules.

Features

AI-Powered Decision Engine: Automates security decision-making using custom Python scripts.

Slack Notifications: Sends alerts and reports directly to Slack channels.

Threat Intelligence Integration: Supports automated threat feed processing and logging.

Modular Design: Easily extendable via ai_engine.py, decision_engine.py, and response_engine.py.

Logging & Monitoring: Centralized logging using built-in logger.py module.

Requirements

Python 3.12+

Virtual Environment (recommended)

Packages listed in requirements.txt

Installation

Clone the repository:

git clone https://github.com/zeeshan494/AI_SOAR-x-Wazuh.git
cd soar-engine

Create a virtual environment:

python3 -m venv venv
source venv/bin/activate

Install required packages:

pip install -r requirements.txt

⚠ Note: Make sure your requirements.txt does not include pip install commands inside it. Only list package names.

Usage

Activate the virtual environment:

source venv/bin/activate

Run the main application:

python app.py

Configure the engine via config.py as needed.

Monitor logs in the logs/ directory.

Project Structure
soar-engine/
├── ai_engine.py
├── decision_engine.py
├── response_engine.py
├── logger.py
├── config.py
├── app.py
├── services/
├── routes/
├── slack_notifier.py
├── tests/
├── logs/
├── requirements.txt
└── venv/
Contributing

Fork the repository.

Create a feature branch: git checkout -b feature-name

Commit your changes: git commit -m "Add feature"

Push to branch: git push origin feature-name

Open a Pull Request.
