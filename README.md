# RESTful API - Capyba Challenge

This repository contains a RESTful API built with Django and Django REST Framework, developed for the Capyba selection process. It provides functionalities for user management, item handling, and various supporting features.

The API includes automated tests, OpenAPI documentation, a database seeding command, Django Admin access, and an endpoint for legal documents.

## Features

*   User Registration & Email Confirmation
*   Token-based Authentication (Login/Logout)
*   User Profile Management (View/Update, including profile picture)
*   Password Change Functionality
*   Item Management (CRUD operations for authenticated & confirmed users)
*   Advanced Item Listing (Pagination, Search, Ordering, Filtering)
*   Automated Tests (`pytest`)
*   OpenAPI (Swagger/Redoc) Documentation (`drf-yasg`)
*   Database Seeding Command
*   Django Admin Interface Access
*   Legal Information Endpoint

## Technologies Used

- **Python** (3.10+)
- **Django**
- **Django REST Framework (DRF)**
- **Database:** PostgreSQL (on Render), SQLite (local default)
- **WSGI Server:** Gunicorn
- **Static Files:** Whitenoise
- **DB Connection:** dj-database-url
- **PostgreSQL Driver:** psycopg2-binary
- **django-filter** (For advanced API filtering)
- **drf-yasg** (For OpenAPI/Swagger documentation generation)
- **Pillow** (For image handling - profile picture)


## Prerequisites

Before you begin, ensure you have the following installed:

- Python (version 3.10 or higher recommended)
- Pip (Python package manager, usually included with Python)
- Git (for cloning the repository)


## Installation and Setup

Follow the steps below to set up the development environment:

1. **Clone the Repository:**

```bash
git clone https://github.com/lucas-jorge/desafioCapyba.git
cd desafioCapyba
```

2. **Create a Virtual Environment:**
It is highly recommended to use a virtual environment to isolate project dependencies and avoid conflicts with other projects.

```bash
python -m venv venv
```

_(You can use a different name instead of `venv` if you prefer)_
3. **Activate the Virtual Environment:**

- On Linux/macOS:

```bash
source venv/bin/activate
```

- On Windows (CMD/PowerShell):

```bash
.\venv\Scripts\activate
```

4. **Install Dependencies:**
Install all required Python libraries listed in the `requirements.txt` file.

```bash
pip install -r requirements.txt
```

5. **Apply Migrations:**
Create the necessary tables in the SQLite database based on the defined models.

```bash
python manage.py migrate
```


## Running the Project

After setup, you can start the Django development server:

```bash
python manage.py runserver
```

The API will be accessible on your local machine, usually at http://127.0.0.1:8000/.

## API Endpoints Overview

Here are some of the base URLs for the API:

*   Authentication: `/api/auth/` (includes `/register/`, `/login/`, `/logout/`)
*   Profile: `/api/profile/`
*   Items: `/api/items/`
*   Legal: `/api/legal/`
*   API Docs (Swagger): `/swagger/`
*   API Docs (Redoc): `/redoc/`

Refer to the full OpenAPI documentation (linked below) for detailed endpoint information.

## Populating with Seed Data (Bonus Feature)

A command is available to populate the database with initial sample data (users and items) for testing purposes.

```bash
python manage.py seed_db
```

This command will create (if they don't exist):

- User: seeduser1@example.com (Password: SeedPass1!), Email Confirmed: Yes
- User: seeduser2@example.com (Password: SeedPass2@), Email Confirmed: No
- Several public and restricted items belonging to these users.

The command is safe to run multiple times (it uses `get_or_create`).

## Django Admin Interface (Bonus Feature)

Basic Django Admin access is configured for managing `CustomUser` and `Item` models.

1. **Create a Superuser**: If you haven't already, create a superuser account to access the admin:

```bash
python manage.py createsuperuser
```

Follow the prompts to set the email (used for login), username, and password.
2. **Access the Admin**: With the development server running, navigate to `/admin/` in your browser:
http://127.0.0.1:8000/admin/
Log in using the superuser credentials you created.

## Legal Information Endpoint (Bonus Feature)

An endpoint is available to retrieve links to the Terms of Service and Privacy Policy documents:

- **URL**: `/api/legal/`
- **Method**: GET
- **Authentication**: Not required.
- **Response**: JSON object containing `terms_of_service_url` and `privacy_policy_url`.


## Running Tests 

To execute the automated tests and verify the API's integrity:

```bash
python manage.py test capy
```

(Or `python manage.py test` to run all tests in the project)

## API Documentation (OpenAPI/Swagger)

The API includes automatically generated interactive documentation. With the server running, access one of the following links in your browser:

- **Swagger UI**: http://127.0.0.1:8000/swagger/
- **Redoc**: http://127.0.0.1:8000/redoc/

In these interfaces, you can explore all endpoints, view request/response details, and even make test calls directly.

**Important Note on Authentication in Swagger UI:**

The default Django REST Framework login/logout buttons visible at the top of the Swagger UI **do not work** with the token-based authentication used in this API. To authenticate your requests within the documentation:

1.  **Obtain a Token:** Use the `/api/api-token-auth/` endpoint (you can find it in the list below). Make a POST request with your `username` (which is your email) and `password`. Copy the `token` value from the response.
2.  **Authorize:** Click the "Authorize" button (usually located near the top right, sometimes represented by a lock icon). In the dialog that appears, paste the token you copied into the `Value` field, prefixed with the word `Token` and a space (e.g., `Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b`). Click "Authorize" again in the dialog.

Now your subsequent requests made through the Swagger UI will be authenticated.

## Deployment (Bonus Feature)

This API is deployed on Render. You can access the live API at:

- **Live API**: https://capyba-api.onrender.com

## Project Structure

- **config/**: Main Django project configuration (settings, root URLs, WSGI/ASGI).
- **capy/**: The core application logic (models, views, serializers, API endpoints, tests, admin config, management commands, etc.).
- **manage.py**: Django's command-line utility for tasks like running the server and migrations.
- **requirements.txt**: List of Python dependencies required for the project.
- **README.md**: This file, providing project documentation.
- **.gitignore**: Specifies intentionally untracked files that Git should ignore.
- **Procfile**: Declares process types for platforms like Render (e.g., web worker).
- **staticfiles/**: Directory where static files are collected for production.
- **db.sqlite3**: The SQLite database file (created after running `migrate`).
- **media/**: (If configured) Directory for user-uploaded files like profile pictures.
- **venv/**: (Recommended) Folder containing the Python virtual environment.
