# capy/urls.py

# Necessary imports from Django and DRF
from django.urls import path
# Import the default DRF view to obtain token
from rest_framework.authtoken import views as authtoken_views

from . import views  # Importa as views do nosso app 'capy'

# Defines a 'namespace' to avoid name conflicts between apps
app_name = 'capy'

# List of URL patterns (endpoints) for the 'capy' app API
urlpatterns = [

    # --- Authentication and User Management ---

    # Endpoint: /api/register/
    # Method: POST
    # Action: Creates a new user. Open to anyone.
    path('register/', views.RegisterView.as_view(), name='register'),

    # Endpoint: /api/api-token-auth/
    # Method: POST
    # Action: Receives 'username' (email) and 'password', returns the token.
    #       This is the "login" endpoint for the token-based API.
    path('api-token-auth/', authtoken_views.obtain_auth_token,
         name='api_token_auth'),

    # Endpoint: /api/profile/
    # Methods: GET, PUT, PATCH
    # Action: GET to view profile. PUT/PATCH to update.
    #       Requires authentication via Token
    path('profile/', views.ProfileView.as_view(), name='profile'),

    # Endpoint: /api/change-password/
    # Method: POST
    # Action: Logged-in user changes their own password.
    #       Requires authentication via Token.
    path('change-password/', views.ChangePasswordView.as_view(),
         name='change-password'),

    # --- Email Confirmation ---

    # Endpoint: /api/email/request-confirmation/
    # Method: POST
    # Action: Requests a new confirmation email.
    #       Requires auth via Token. User not confirmed.
    path(
        'email/request-confirmation/',
        views.RequestConfirmationEmailView.as_view(),
        name='request-confirmation-email'
    ),
    path(
        'email/validate-confirmation/',
        views.ValidateConfirmationView.as_view(),
        name='validate-confirmation-email',
    ),

    # --- Items ---

    # Endpoint: /api/items/public/
    # Methods: GET, POST
    # Action: GET to list public items.
    #       POST to create a new item (requires authentication).
    #       The 'owner' is automatically associated with the token user.
    path(
        'items/public/',
        views.PublicItemListView.as_view(),
        name='public-item-list'
    ),
    path(
        'items/restricted/',
        views.RestrictedItemListView.as_view(),
        name='restricted-item-list'
    ),
    path('legal/',
         views.LegalInfoView.as_view(),
         name='legal-info'),
]
