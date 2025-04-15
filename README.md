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

The API will be accessible on your local machine, usually at http://127.0.0.1:8000/. The API endpoints are available under the /api/ prefix (e.g., http://127.0.0.1:8000/api/register/).

6.  **Populating with Seed Data (Optional)**
    A command is available to populate the database with initial sample data (users and items) for testing purposes.
    ```bash
    python manage.py seed_db
    ```
    This command will create (if they don't exist):
    * User: ```bash seeduser1@example.com ```(Password: ```bash SeedPass1!```), Email confirmed: Yes
    * User: ```bash seeduser2@example.com ```(Password: ```bash SeedPass2@```), Email confirmed: No
    * Several public and restricted items related to these users.

## Running Tests

To execute the automated tests and verify the API's integrity:

```bash python manage.py test ```

## API Documentation (Swagger)

The API includes automatically generated interactive documentation. With the server running, access one of the following links in your browser:

* Swagger UI: ```bash http://127.0.0.1:8000/swagger/ ```