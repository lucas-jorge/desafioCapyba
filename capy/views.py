# capy/views.py

from rest_framework import generics, permissions, filters, status
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination  # Import pagination
from django_filters.rest_framework import DjangoFilterBackend
import uuid  # Para gerar tokens UUID
from django.utils import timezone  # Para registrar o tempo
from rest_framework.views import APIView
from datetime import timedelta

from .models import CustomUser, Item
from .serializers import (  # Formatted import
    UserSerializer,
    RegisterSerializer,
    ItemSerializer,
    ChangePasswordSerializer,
    ValidateConfirmationSerializer,
)
from .permissions import IsEmailConfirmed

# --- Autenticação e Usuário ---


class RegisterView(generics.CreateAPIView):
    """
    Endpoint para registro de novos usuários. Aberto a todos.
    Retorna os dados do usuário criado usando UserSerializer.
    """
    queryset = CustomUser.objects.all()
    permission_classes = (permissions.AllowAny,)
    # Serializer para validar ENTRADA e criar
    serializer_class = RegisterSerializer

    # Sobrescrevendo o método 'create' para customizar a RESPOSTA
    def create(self, request, *args, **kwargs):
        # 1. Pega o serializer de ENTRADA (RegisterSerializer) com os dados
        # da requisição
        serializer = self.get_serializer(data=request.data)
        # 2. Valida os dados de entrada (ex: senhas batem, campos obrigatórios)
        serializer.is_valid(raise_exception=True)
        # 3. Cria o usuário no banco. O método padrão perform_create chama
        # serializer.save() e a instância criada fica disponível em
        # serializer.instance
        self.perform_create(serializer)
        # 4. Pega a instância do usuário que acabou de ser criado
        user_instance = serializer.instance
        # 5. Cria um NOVO serializer (UserSerializer) para formatar a SAÍDA
        # (resposta). Passamos a instância do usuário criado para ele.
        response_serializer = UserSerializer(
            user_instance, context=self.get_serializer_context()
        )
        # 6. Pega os cabeçalhos padrão de sucesso (ex: Location, se aplicável)
        headers = self.get_success_headers(response_serializer.data)
        # 7. Retorna a Resposta HTTP 201 Created com os dados formatados
        # pelo UserSerializer (que inclui 'id' e 'email_confirmed')
        return Response(
            response_serializer.data, status=status.HTTP_201_CREATED,
            headers=headers
        )


class ProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = (permissions.IsAuthenticated,)  # Requer Token válido

    def get_object(self):
        return self.request.user


# --- Itens ---


class PublicItemListView(generics.ListCreateAPIView):
    serializer_class = ItemSerializer
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
    pagination_class = PageNumberPagination  # Explicitly set pagination
    page_size_query_param = 'page_size'
    # Definir o queryset base aqui é opcional se get_queryset for simples,
    # mas podemos manter para clareza inicial.
    queryset = Item.objects.filter(is_public=True)

    # Configuração dos filtros, busca e ordenação
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    # Deixe django-filter cuidar do filtro por owner e is_public
    filterset_fields = ['owner', 'is_public']
    search_fields = ['title', 'description']
    ordering_fields = ['title', 'created_at']
    ordering = ['-created_at']

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


# --- Change Password View ---


class ChangePasswordView(generics.UpdateAPIView):
    """Endpoint para alterar a senha do usuário autenticado."""
    serializer_class = ChangePasswordSerializer
    model = CustomUser  # Necessário para UpdateAPIView se não usar queryset
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self, queryset=None):
        # Garante que o objeto sendo "atualizado" é o próprio usuário logado
        return self.request.user

    def update(self, request, *args, **kwargs):
        # Define self.object como o usuário logado
        self.object = self.get_object()
        # Pega o serializer com os dados da requisição
        serializer = self.get_serializer(data=request.data)

        # Valida os dados do serializer (ex: new_password1 == new_password2)
        if serializer.is_valid():
            # Check old password - USANDO validated_data
            if not self.object.check_password(
                serializer.validated_data.get("old_password")  # <-- CORRIGIDO
            ):
                # Retorna erro se a senha antiga não bater
                return Response(
                    {"old_password": ["Senha antiga incorreta."]},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Define a nova senha (hash automático) - USANDO validated_data
            self.object.set_password(
                serializer.validated_data.get("new_password1")  # <-- CORRIGIDO
            )
            self.object.save()

            # Retorna resposta de sucesso
            response = {
                "status": "success",
                "code": status.HTTP_200_OK,
                "message": "Password updated successfully",
                "data": [],
            }
            return Response(response)

        # Retorna os erros de validação do serializer se is_valid() falhar
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# --- Views para Confirmação de E-mail ---


class RequestConfirmationEmailView(APIView):
    """
    Endpoint para um usuário logado solicitar um novo token
    de confirmação de e-mail.
    """
    # Só usuários logados podem solicitar
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user

        # 1. Verifica se o e-mail já está confirmado
        if user.email_confirmed:
            return Response(
                {"message": "Seu e-mail já está confirmado."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 2. Gera um novo token UUID
        new_token = uuid.uuid4()

        # 3. Atualiza o usuário com o novo token e a data/hora atual
        user.confirmation_token = new_token
        user.token_created_at = timezone.now()
        # Otimização: salva só os campos alterados
        user.save(update_fields=['confirmation_token', 'token_created_at'])

        # 4. Simula o envio de e-mail (etapa futura seria enviar de verdade)
        # Por agora, apenas retornamos o token na resposta para testes.
        print(f"--- SIMULANDO ENVIO DE EMAIL para {user.email} ---")
        print(f"--- Token: {new_token} ---")
        # Em um projeto real, aqui você chamaria uma função para enviar
        # um e-mail contendo um link com este token.
        # Ex: send_confirmation_email(user, new_token)

        return Response(
            {
                "message": "Token de confirmação gerado e 'enviado' "
                           "(simulado). Verifique o console ou use o token "
                           "abaixo para validar.",
                "token": str(new_token)  # Retorna o token como string
            },
            status=status.HTTP_200_OK
        )


class ValidateConfirmationView(APIView):
    """
    Endpoint para validar o token de confirmação de e-mail
    enviado pelo usuário.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user

        # 1. Validar se o token foi enviado no corpo da requisição
        serializer = ValidateConfirmationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

        provided_token = serializer.validated_data['token']

        # 2. Verificar se o e-mail já está confirmado
        if user.email_confirmed:
            # Ou 400, dependendo da preferência
            return Response(
                {"message": "Este e-mail já foi confirmado anteriormente."},
                status=status.HTTP_200_OK
            )

        # 3. Verificar se existe um token pendente para este usuário
        if not user.confirmation_token or not user.token_created_at:
            return Response(
                {"error": "Nenhum processo de confirmação pendente encontrado."
                          "Solicite um novo token."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 4. (Opcional mas recomendado) Verificar expiração do token (ex: 24h)
        expiration_duration = timedelta(hours=24)
        now = timezone.now()
        if now > user.token_created_at + expiration_duration:
            # Token expirou, limpar token antigo e pedir novo
            user.confirmation_token = None
            user.token_created_at = None
            user.save(update_fields=['confirmation_token', 'token_created_at'])
            return Response(
                {"error": "Token de confirmação expirado. "
                          "Por favor, solicite um novo."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 5. Comparar o token fornecido com o token armazenado
        #    Comparar como strings para evitar problemas entre UUID e string
        if str(provided_token) == str(user.confirmation_token):
            # Token VÁLIDO! Confirmar o e-mail e limpar os campos do token
            user.email_confirmed = True
            user.confirmation_token = None
            user.token_created_at = None
            user.save(
                update_fields=[
                    'email_confirmed', 'confirmation_token',
                    'token_created_at'
                ]
            )

            return Response({"message": "E-mail confirmado com sucesso!"},
                            status=status.HTTP_200_OK)
        else:
            # Token inválido
            return Response({"error": "Token de confirmação inválido."},
                            status=status.HTTP_400_BAD_REQUEST)


class RestrictedItemListView(generics.ListAPIView):
    """
    Endpoint para listar itens restritos (is_public=False).
    Acessível apenas por usuários autenticados E com e-mail confirmado.
    Suporta paginação, busca, ordenação e filtragem (igual à lista pública).
    """
    serializer_class = ItemSerializer  # Mesmo serializer da lista pública

    # Permissões: Precisa estar autenticado E ter email confirmado
    permission_classes = [permissions.IsAuthenticated, IsEmailConfirmed]

    # Queryset base: Filtra apenas itens NÃO públicos
    queryset = Item.objects.filter(is_public=False)

    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter
    ]
    filterset_fields = ['owner', 'is_public']  # Permite filtrar restritos
    search_fields = ['title', 'description']
    ordering_fields = ['title', 'created_at']
    ordering = ['-created_at']  # Ordenação padrão
