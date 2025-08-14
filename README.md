# Web Vulnerability Scanner

A professional, Flask-based web vulnerability scanner designed to automate the detection of common security flaws. This upgraded version features a robust scanning engine, asynchronous task handling with Celery, and headless browser technology for high-accuracy XSS detection.

## Key Features

- **Modern Web Interface**: An intuitive UI built with Tailwind CSS to manage scans and visualize results.
- **Asynchronous Scanning**: Utilizes Celery and Redis to perform heavy scanning tasks in the background without blocking the user interface.
- **Advanced Scanning Engine**:
- **Vulnerability Support**: Detects SQL Injection (Error-based, Time-based), Command Injection (Output-based, Time-based), and Cross-Site Scripting (XSS).
- **High-Accuracy XSS Detection**: Uses a headless browser (Playwright) to render pages and confirm JavaScript execution, virtually eliminating false positives.
- **Comprehensive Target Discovery**: Crawls both GET parameters and POST forms to discover a wide range of potential targets.
- **Data Visualization**: Scan results are displayed using charts (Chart.js) for a clear and immediate overview of the security posture.
- **Secure and Professional**: Manages sensitive credentials and configuration via environment variables (`.env` file).

## Tech Stack

- **Backend**: Python, Flask, Celery
- **Frontend**: HTML, Tailwind CSS, JavaScript, Chart.js
- **Database**: PostgreSQL (easily adaptable to SQLite or MySQL)
- **Message Broker**: Redis
- **Core Python Libraries**: `requests`, `beautifulsoup4`, `sqlalchemy`, `playwright`

## Getting Started

Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Python 3.8+
- A running Redis Server instance.
- A running PostgreSQL Server instance.
- A test environment to scan (e.g., [DVWA](https://dvwa.co.uk/) or [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) running in Docker).

### Installation and Setup

1.  **Clone the repository:**

    ```bash
    git clone <your-repo-url>
    cd <your-repo-folder>
    ```

2.  **Create and activate a virtual environment (recommended):**

    ```bash
    # For Windows
    python -m venv venv
    venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required packages:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Install browser binaries for Playwright:**

    ```bash
    playwright install
    ```

5.  **Configure environment variables:**

    - Copy the example `.env.example` file to a new file named `.env`:
      ```bash
      cp .env.example .env
      ```
    - Open the `.env` file and edit the values to match your environment, especially the `DATABASE_URL` and any target credentials.

6.  **Initialize the database:**
    - Run the following command to create the necessary tables in your PostgreSQL database:
      ```bash
      python create_db.py
      ```

### Running the Application

The application requires three separate processes running in three different terminals.

1.  **Start the Redis Server:**

    - Make sure your Redis instance is running.

2.  **Start the Celery Worker:**

    - Open a new terminal, activate the virtual environment, and run:
      ```bash
      celery -A task.celery worker --loglevel=info --pool=eventlet
      ```
    - **Note:** `--pool=eventlet` is crucial for Celery to handle network-based tasks efficiently.

3.  **Start the Flask Application:**

    - Open another terminal, activate the virtual environment, and run:
      ```bash
      flask run
      ```

4.  **Access the Application:**
    - Open your web browser and navigate to `http://127.0.0.1:5000`. You can now start scanning!
