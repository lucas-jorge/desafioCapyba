# RESTful API - Capyba Challenge

This is a RESTful API developed as part of the Capyba technical challenge for their selection process. The API implements features such as user registration, authentication (via Token), profile management, email confirmation, and item listing/creation with advanced features like pagination, search, ordering, and filtering.

## Technologies Used

* **Python** (3.10+)
* **Django**
* **Django REST Framework (DRF)**
* **SQLite** (Default database)
* **django-filter** (For advanced API filtering)
* **drf-yasg** (For OpenAPI/Swagger documentation generation)
* **Pillow** (For image handling - profile picture)

## Prerequisites

Before you begin, ensure you have the following installed:

* Python (version 3.10 or higher recommended)
* Pip (Python package manager, usually included with Python)
* Git (for cloning the repository)

## Installation and Setup

Follow the steps below to set up the development environment:

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/lucas-jorge/desafioCapyba.git] # Replace with your repository URL
    cd project-folder-name      # Navigate into the created folder
    ```

2.  **Create a Virtual Environment:**
    It is highly recommended to use a virtual environment to isolate project dependencies.
    ```bash
    python -m venv venv
    ```
    *(You can use a different name instead of `venv` if you prefer)*

3.  **Activate the Virtual Environment:**
    * On Linux/macOS:
        ```bash
        source venv/bin/activate
        ```
    * On Windows (CMD/PowerShell):
        ```bash
        .\venv\Scripts\activate
        ```

4.  **Install Dependencies:**
    Install all required Python libraries listed in the `requirements.txt` file.
    ```bash
    pip install -r requirements.txt
    ```

5.  **Apply Migrations:**
    Create the necessary tables in the SQLite database based on the defined models.
    ```bash
    python manage.py migrate
    ```

## Running the Project

After setup, you can start the Django development server:

```bash
python manage.py runserver

Okay, understood. Here is the complete Markdown content for the English README.md file, based on our discussion and the project's current state.

Generated on: Tuesday, April 15, 2025 at 10:14 AM -03 (Recife, State of Pernambuco, Brazil).

Instructions:

Create or replace the README.md file in your project's root directory.
Copy and paste the text below into the file.
Review and customize any placeholders like [YOUR_GITHUB_URL] or other specific details if necessary.
Make sure your requirements.txt file is up-to-date (pip freeze > requirements.txt).
Save the README.md file and commit both (README.md and potentially requirements.txt) to your GitHub repository (git add ., git commit, git push).
Markdown

# RESTful API - Capyba Challenge

This is a RESTful API developed as part of the Capyba technical challenge for their selection process[cite: 1]. The API implements features such as user registration[cite: 8], authentication (via Token), profile management[cite: 14], email confirmation[cite: 15], and item listing/creation with advanced features like pagination[cite: 9], search[cite: 9], ordering[cite: 13], and filtering[cite: 12]. It also includes automated tests [cite: 17] and OpenAPI documentation[cite: 17].

## Technologies Used

* **Python** (3.10+)
* **Django**
* **Django REST Framework (DRF)**
* **SQLite** (Default database)
* **django-filter** (For advanced API filtering)
* **drf-yasg** (For OpenAPI/Swagger documentation generation)
* **Pillow** (For image handling - profile picture)

## Prerequisites

Before you begin, ensure you have the following installed:

* Python (version 3.10 or higher recommended)
* Pip (Python package manager, usually included with Python)
* Git (for cloning the repository)

## Installation and Setup

Follow the steps below to set up the development environment:

1.  **Clone the Repository:**
    ```bash
    git clone [YOUR_GITHUB_URL] # Replace with your repository URL
    cd project-folder-name      # Navigate into the created folder
    ```

2.  **Create a Virtual Environment:**
    It is highly recommended to use a virtual environment to isolate project dependencies.
    ```bash
    python -m venv venv
    ```
    *(You can use a different name instead of `venv` if you prefer)*

3.  **Activate the Virtual Environment:**
    * On Linux/macOS:
        ```bash
        source venv/bin/activate
        ```
    * On Windows (CMD/PowerShell):
        ```bash
        .\venv\Scripts\activate
        ```

4.  **Install Dependencies:**
    Install all required Python libraries listed in the `requirements.txt` file.
    ```bash
    pip install -r requirements.txt
    ```

5.  **Apply Migrations:**
    Create the necessary tables in the SQLite database based on the defined models.
    ```bash
    python manage.py migrate
    ```

## Running the Project

After setup, you can start the Django development server:

```bash
python manage.py runserver


The API will be accessible on your local machine, usually at http://127.0.0.1:8000/. The API endpoints are available under the /api/ prefix (e.g., http://127.0.0.1:8000/api/register/).

## Running Tests

To execute the automated tests  and verify the API's integrity:

```bash
python manage.py test

## API Documentation (OpenAPI/Swagger)

The API includes automatically generated interactive documentation. With the server running, access one of the following links in your browser:

Swagger UI:
```bash
http://127.0.0.1:8000/swagger/

In these interfaces, you can explore all endpoints, view request/response details, and even make test calls directly.
