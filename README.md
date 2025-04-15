# RESTful API - Capyba Challenge

This is a RESTful API developed as part of the Capyba technical challenge for their selection process. The API implements features such as user registration, authentication (via Token), profile management, password change, email confirmation, restricted resource access based on email confirmation, and item listing/creation with advanced features like pagination, search, ordering, and filtering.

It also includes automated tests, OpenAPI documentation, a database seeding command, Django Admin access, and an endpoint for legal documents.

## Technologies Used

- **Python** (3.10+)
- **Django**
- **Django REST Framework (DRF)**
- **SQLite** (Default database)
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
git clone [https://github.com/lucas-jorge/desafioCapyba.git]
cd project-folder-name
```

2. **Create a Virtual Environment:**
It is highly recommended to use a virtual environment to isolate project dependencies.

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

The API will be accessible on your local machine, usually at http://127.0.0.1:8000/. The API endpoints are available under the `/api/` prefix (e.g., http://127.0.0.1:8000/api/register/).

## Populating with Seed Data (Optional Bonus)

A command is available to populate the database with initial sample data (users and items) for testing purposes.

```bash
python manage.py seed_db
```

This command will create (if they don't exist):

- User: seeduser1@example.com (Password: SeedPass1!), Email Confirmed: Yes
- User: seeduser2@example.com (Password: SeedPass2@), Email Confirmed: No
- Several public and restricted items belonging to these users.

The command is safe to run multiple times (it uses get_or_create).

## Django Admin Interface (Bonus Feature)

Basic Django Admin access is configured for managing CustomUser and Item models.

1. **Create a Superuser**: If you haven't already, create a superuser account to access the admin:

```bash
python manage.py createsuperuser
```

Follow the prompts to set the email (used for login), username, and password.
2. **Access the Admin**: With the development server running, navigate to `/admin/` in your browser:
http://127.0.0.1:8000/admin/
Log in using the superuser credentials you created.

## Legal Information Endpoint (Bonus Feature)

An endpoint is available to retrieve links to the Terms of Service and Privacy Policy documents

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

## Project Structure

- **config/**: Contains the main Django project settings (`settings.py`) and root URL configuration (`urls.py`).
- **capy/**: The Django app containing the core API logic (models, views, serializers, app-specific URLs, tests, admin config, management commands, etc.).
- **manage.py**: Django's command-line utility.
- **requirements.txt**: List of Python dependencies.
- **README.md**: This file.
- **.gitignore**: Files and folders ignored by Git.
- **db.sqlite3**: SQLite database file (created after migrate).
- **media/**: Folder where profile images are saved (if MEDIA_ROOT is configured).
