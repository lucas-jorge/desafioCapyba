# capy/views.py

import uuid
from datetime import timedelta

from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics, permissions, filters, status, serializers
from rest_framework.request import Request  # For type hinting request
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView

# Import Models
from .models import CustomUser, Item

# Import Serializers
from .serializers import (
    UserSerializer,
    RegisterSerializer,
    ItemSerializer,
    ChangePasswordSerializer,
    ValidateConfirmationSerializer,
)

# Import Permissions
from .permissions import IsEmailConfirmed


# --- Autenticação e Usuário ---

class RegisterView(generics.CreateAPIView):
    """
    Endpoint para registro de novos usuários. Aberto a todos.
    Retorna os dados do usuário criado usando UserSerializer.
    """
    queryset = CustomUser.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = RegisterSerializer

    def create(self, request: Request, 
               *args: tuple, **kwargs: dict) -> Response:
        """
        Cria um usuário e retorna seus dados via UserSerializer.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        # Assume serializer.instance is set after perform_create
        user_instance: CustomUser = serializer.instance
        response_serializer = UserSerializer(
            user_instance, context=self.get_serializer_context()
        )
        headers = self.get_success_headers(response_serializer.data)
        return Response(
            response_serializer.data, status=status.HTTP_201_CREATED,
            headers=headers
        )


class ProfileView(generics.RetrieveUpdateAPIView):
    """
    Endpoint para ver (GET) e atualizar (PUT/PATCH) o perfil do usuário autenticado.
    """
    serializer_class = UserSerializer
    permission_classes = (permissions.IsAuthenticated,)  # Requer Token válido

    def get_object(self) -> AbstractBaseUser:
        """
        Retorna o usuário autenticado associado à requisição.
        """
        # request.user can be User or AnonymousUser; IsAuthenticated ensures User
        return self.request.user


# --- Itens ---

class PublicItemListView(generics.ListCreateAPIView):
    """
    Endpoint para listar itens públicos (GET) e criar novos itens (POST).
    GET é aberto, POST requer autenticação por Token.
    Suporta paginação, busca, ordenação e filtragem.
    """
    serializer_class = ItemSerializer
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
    pagination_class = PageNumberPagination
    page_size_query_param = 'page_size'  # Permite override via ?page_size=X
    queryset = Item.objects.filter(is_public=True)

    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = ['owner', 'is_public']
    search_fields = ['title', 'description']
    ordering_fields = ['title', 'created_at']
    ordering = ['-created_at']  # Ordenação padrão

    def perform_create(self, serializer: serializers.Serializer) -> None:
        """
        Associa o item sendo criado ao usuário autenticado.
        """
        serializer.save(owner=self.request.user)


# --- Change Password View ---

class ChangePasswordView(generics.UpdateAPIView):
    """Endpoint para alterar a senha do usuário autenticado."""
    serializer_class = ChangePasswordSerializer
    model = CustomUser
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self, queryset=None) -> AbstractBaseUser:
        """
        Retorna o usuário autenticado como o objeto a ser "atualizado".
        """
        return self.request.user

    def update(self, request: Request,
               *args: tuple, **kwargs: dict) -> Response:
        """
        Lida com a requisição PUT/PATCH para alterar a senha.
        """
        self.object = self.get_object()
        user: CustomUser = self.object  # Type hint for clarity

        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)

            old_password = serializer.validated_data.get("old_password")

            # Validação Adicional: Verificar a Senha Antiga
            if not user.check_password(old_password):
                raise serializers.ValidationError(
                    {"old_password": ["Senha antiga incorreta."]}
                )

            # Define a nova senha (hash automático)
            user.set_password(
                serializer.validated_data.get("new_password1")
            )
            user.save()

            # Retorna resposta de sucesso
            response_data = {
                "status": "success",
                "code": status.HTTP_200_OK,
                "message": "Password updated successfully",
                "data": [],
            }
            return Response(response_data)

        except serializers.ValidationError:
            # Re-raise para DRF tratar e retornar 400
            raise
        except Exception as e:
            # Logar erro inesperado seria bom em produção
            print(f"Erro inesperado em ChangePasswordView: {e}")
            # Re-raise para retornar 500 Internal Server Error
            raise


# --- Views para Confirmação de E-mail ---

class RequestConfirmationEmailView(APIView):
    """
    Endpoint para um usuário logado solicitar um novo token
    de confirmação de e-mail.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: tuple, **kwargs: dict) -> Response:
        """
        Gera e salva um token de confirmação para o usuário. Simula envio.
        """
        user: CustomUser = request.user  # type: ignore

        if user.email_confirmed:
            return Response(
                {"message": "Seu e-mail já está confirmado."},
                status=status.HTTP_400_BAD_REQUEST
            )

        new_token = uuid.uuid4()
        user.confirmation_token = new_token
        user.token_created_at = timezone.now()
        user.save(update_fields=['confirmation_token', 'token_created_at'])

        # Simulação de envio (imprime no console)
        print(f"--- SIMULANDO ENVIO DE EMAIL para {user.email} ---")
        print(f"--- Token: {new_token} ---")

        return Response(
            {"message": "Token de confirmação gerado e 'enviado' (simulado). "
                        "Verifique o console.",
             "token": str(new_token)},
            status=status.HTTP_200_OK
        )


class ValidateConfirmationView(APIView):
    """
    Endpoint para validar o token de confirmação de e-mail
    enviado pelo usuário no corpo da requisição.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, *args: tuple, **kwargs: dict) -> Response:
        """
        Valida o token e confirma o email do usuário se válido e não expirado.
        """
        user: CustomUser = request.user  # type: ignore
        serializer = ValidateConfirmationSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, 
                            status=status.HTTP_400_BAD_REQUEST)

        provided_token: uuid.UUID = serializer.validated_data['token']

        if user.email_confirmed:
            return Response(
                {"message": "Este e-mail já foi confirmado anteriormente."},
                status=status.HTTP_200_OK
            )

        if not user.confirmation_token or not user.token_created_at:
            return Response(
                {"error": "Nenhum processo de confirmação pendente encontrado. "
                          "Solicite um novo token."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Verificar expiração (ex: 24 horas)
        expiration_duration = timedelta(hours=24)
        now = timezone.now()
        is_expired = now > user.token_created_at + expiration_duration

        if is_expired:
            user.confirmation_token = None
            user.token_created_at = None
            user.save(update_fields=['confirmation_token', 'token_created_at'])
            return Response(
                {"error": "Token de confirmação expirado. "
                          "Por favor, solicite um novo."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Comparar tokens
        if str(provided_token) == str(user.confirmation_token):
            user.email_confirmed = True
            user.confirmation_token = None
            user.token_created_at = None
            user.save(
                update_fields=[
                    'email_confirmed', 'confirmation_token', 'token_created_at'
                ]
            )
            return Response({"message": "E-mail confirmado com sucesso!"},
                            status=status.HTTP_200_OK)
        else:
            return Response({"error": "Token de confirmação inválido."},
                            status=status.HTTP_400_BAD_REQUEST)


class RestrictedItemListView(generics.ListAPIView):
    """
    Endpoint para listar itens restritos (is_public=False).
    Acessível apenas por usuários autenticados E com e-mail confirmado.
    Suporta paginação, busca, ordenação e filtragem (igual à lista pública).
    """
    serializer_class = ItemSerializer
    permission_classes = [permissions.IsAuthenticated, IsEmailConfirmed]
    queryset = Item.objects.filter(is_public=False)

    # Reutiliza configurações da lista pública
    pagination_class = PageNumberPagination
    page_size_query_param = 'page_size'
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter
    ]
    filterset_fields = ['owner', 'is_public']
    search_fields = ['title', 'description']
    ordering_fields = ['title', 'created_at']
    ordering = ['-created_at']
