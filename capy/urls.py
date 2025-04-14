# capy/urls.py

# Importações necessárias do Django e DRF
from django.urls import path
# Importa a view padrão do DRF para obter token
from rest_framework.authtoken import views as authtoken_views

from . import views  # Importa as views do nosso app 'capy'

# Define um 'namespace' para evitar conflito de nomes entre apps
app_name = 'capy'

# Lista de padrões de URL (endpoints) para a API do app 'capy'
urlpatterns = [

    # --- Autenticação e Gerenciamento de Usuário ---

    # Endpoint: /api/register/
    # Método: POST
    # Ação: Cria um novo usuário. Aberto para qualquer um.
    path('register/', views.RegisterView.as_view(), name='register'),

    # Endpoint: /api/api-token-auth/
    # Método: POST
    # Ação: Recebe 'username' (email) e 'password', retorna o token.
    #       Este é o endpoint de "login" para a API baseada em token.
    path('api-token-auth/', authtoken_views.obtain_auth_token,
         name='api_token_auth'),

    # Endpoint: /api/profile/
    # Métodos: GET, PUT, PATCH
    # Ação: GET para ver o perfil. PUT/PATCH para atualizar.
    #       Requer autenticação via Token (Header: Authorization: Token <token>).
    path('profile/', views.ProfileView.as_view(), name='profile'),

    # Endpoint: /api/change-password/
    # Método: POST
    # Ação: Usuário logado altera a própria senha.
    #       Requer autenticação via Token.
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),

    # --- Confirmação de E-mail ---

    # Endpoint: /api/email/request-confirmation/
    # Método: POST
    # Ação: Solicita novo email de confirmação.
    #       Requer auth via Token. Usuário não confirmado.
    path('email/request-confirmation/',
         views.RequestConfirmationEmailView.as_view(),
         name='request-confirmation-email'),
    
     path('email/validate-confirmation/', views.ValidateConfirmationView.as_view(), name='validate-confirmation-email'),


    # --- Itens ---

    # Endpoint: /api/items/public/
    # Métodos: GET, POST
    # Ação: GET para listar itens públicos.
    #       POST para criar um novo item (requer autenticação).
    #       O 'owner' é associado automaticamente ao usuário do token.
    path('items/public/', views.PublicItemListView.as_view(),
         name='public-item-list'),

]
