# capy/tests.py

import uuid
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase, APIClient  # APIClient importado
from rest_framework.authtoken.models import Token

from .models import CustomUser, Item


# --- Helper Function (pode ficar fora das classes) ---
# (Opcional, mas pode limpar os setups)
def create_test_user(
    username: str, email: str, password: str, confirmed: bool = False
) -> CustomUser:
    """Cria um usuário de teste."""
    user = CustomUser.objects.create_user(
        username=username,
        email=email,
        password=password,
        first_name=username.capitalize(),
        last_name="Test",
        email_confirmed=confirmed
    )
    if confirmed:
        # Apenas para garantir que save() foi chamado após a confirmação manual
        user.save()
    return user


class BaseAPITestCase(APITestCase):
    """ Classe base com métodos auxiliares. """
    client: APIClient  # Type hint
    user: CustomUser
    token: Token

    def _get_token_for_user(self, user: CustomUser, password: str) -> Token:
        """ Obtém ou cria um token para um usuário. """
        token, _ = Token.objects.get_or_create(user=user)
        return token

    def _authenticate_client(self, token: Token) -> None:
        """ Configura o cliente de teste com o token de autenticação. """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')

    def _clear_authentication(self) -> None:
        """ Limpa a autenticação do cliente de teste. """
        self.client.credentials()


class UserRegistrationLoginTests(BaseAPITestCase):
    """ Testes para registro e obtenção de token. """

    def setUp(self) -> None:
        self.register_url = reverse('capy:register')
        self.token_url = reverse('capy:api_token_auth')
        self.register_data = {
            "username": "testregistrar",
            "email": "testregistrar@example.com",
            "first_name": "Test",
            "last_name": "Registrar",
            "password": "StrongPassword123",
            "password2": "StrongPassword123",
        }
        self.login_user = create_test_user(
            'logintestuser', 'logintest@example.com', 'LoginPassword123'
        )

    def test_registration_success(self) -> None:
        """ Testa registro bem-sucedido. """
        response = self.client.post(
            self.register_url, self.register_data, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user_exists = CustomUser.objects.filter(
            email=self.register_data['email']
        ).exists()
        self.assertTrue(user_exists)
        user = CustomUser.objects.get(email=self.register_data['email'])
        self.assertFalse(user.email_confirmed)
        self.assertIn('id', response.data)
        self.assertEqual(response.data['email'], self.register_data['email'])
        self.assertNotIn('password', response.data)

    def test_registration_fail_duplicates(self) -> None:
        """ Testa falha no registro com email ou username duplicado. """
        # Email duplicado
        dup_email_data = self.register_data.copy()
        dup_email_data['email'] = self.login_user.email
        response_email = self.client.post(
            self.register_url, dup_email_data, format='json'
        )
        self.assertEqual(
            response_email.status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertIn('email', response_email.data)

        # Username duplicado
        dup_username_data = self.register_data.copy()
        dup_username_data['username'] = self.login_user.username
        response_uname = self.client.post(
            self.register_url, dup_username_data, format='json'
        )
        self.assertEqual(
            response_uname.status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertIn('username', response_uname.data)

        # Garante que só o usuário do setup existe
        self.assertEqual(CustomUser.objects.count(), 1)

    def test_registration_fail_password_mismatch(self) -> None:
        """ Testa falha no registro com senhas não coincidentes. """
        mismatch_data = self.register_data.copy()
        mismatch_data['password2'] = 'DifferentPassword123'
        response = self.client.post(
            self.register_url, mismatch_data, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password2', response.data)
        self.assertEqual(CustomUser.objects.count(), 1)

    def test_token_obtain_success(self) -> None:
        """ Testa obtenção de token bem-sucedida. """
        login_data = {
            'username': self.login_user.email,
            'password': 'LoginPassword123'
        }
        response = self.client.post(self.token_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertTrue(response.data['token'])

    def test_token_obtain_fail_wrong_credentials(self) -> None:
        """ Testa falha na obtenção de token com credenciais erradas. """
        # Senha errada
        wrong_pw_data = {
            'username': self.login_user.email, 'password': 'Wrong'
        }
        response_pw = self.client.post(
            self.token_url, wrong_pw_data, format='json'
        )
        self.assertEqual(response_pw.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response_pw.data)

        # Usuário inexistente
        non_user_data = {'username': 'nosuch@e.com', 'password': 'pw'}
        response_user = self.client.post(
            self.token_url, non_user_data, format='json'
        )
        self.assertEqual(
            response_user.status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertIn('non_field_errors', response_user.data)


class ProfileAPITests(BaseAPITestCase):  # Herda da Base para helpers
    """ Testes para perfil e alteração de senha. """

    def setUp(self) -> None:
        self.user = create_test_user(
            'profileuser', 'profile@example.com', 'TestPassword123'
        )
        self.password = 'TestPassword123'
        self.token = self._get_token_for_user(self.user, self.password)
        self.profile_url = reverse('capy:profile')
        self.change_password_url = reverse('capy:change-password')

    def test_get_profile(self) -> None:
        """ Testa visualização e falha de visualização do perfil. """
        # Sucesso autenticado
        self._authenticate_client(self.token)
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)

        # Falha não autenticado
        self._clear_authentication()
        response_unauth = self.client.get(self.profile_url)
        self.assertEqual(
            response_unauth.status_code, status.HTTP_401_UNAUTHORIZED
        )

    def test_update_profile_patch(self) -> None:
        """ Testa atualização parcial (PATCH) e falha sem auth. """
        # Sucesso autenticado
        self._authenticate_client(self.token)
        update_data = {'first_name': 'Profile Updated'}
        response = self.client.patch(
            self.profile_url, update_data, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Profile Updated')
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Profile Updated')

        # Falha não autenticado
        self._clear_authentication()
        response_unauth = self.client.patch(
            self.profile_url, update_data, format='json'
        )
        self.assertEqual(
            response_unauth.status_code, status.HTTP_401_UNAUTHORIZED
        )

    def test_change_password(self) -> None:
        """ Testa alteração de senha (sucesso e falhas principais). """
        self._authenticate_client(self.token)
        new_password = "NewSecurePassword456!"

        # --- Sucesso ---
        data_ok = {
            "old_password": self.password,
            "new_password1": new_password, "new_password2": new_password
        }
        response_ok = self.client.put(
            self.change_password_url, data_ok, format='json'
        )
        self.assertEqual(response_ok.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))
        # Atualiza self.password para próximo teste de falha
        self.password = new_password

        # --- Falha: Senha Antiga Errada ---
        data_wrong_old = {
            "old_password": "WRONG_OLD_PASSWORD",
            "new_password1": "AnotherNew",
            "new_password2": "AnotherNew",
        }
        response_wrong_old = self.client.put(
            self.change_password_url, data_wrong_old, format='json'
        )
        self.assertEqual(
            response_wrong_old.status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertIn('old_password', response_wrong_old.data)

        # --- Falha: Novas Senhas Não Coincidem ---
        data_mismatch = {
            "old_password": self.password,  # Usa a nova senha (atual)
            "new_password1": "AnotherNew",
            "new_password2": "MISMATCH",
        }
        response_mismatch = self.client.put(
            self.change_password_url, data_mismatch, format='json'
        )
        self.assertEqual(
            response_mismatch.status_code, status.HTTP_400_BAD_REQUEST
        )
        self.assertIn('new_password2', response_mismatch.data)

        # --- Falha: Não Autenticado ---
        self._clear_authentication()
        response_unauth = self.client.put(
            self.change_password_url, data_ok, format='json'
        )
        self.assertEqual(
            response_unauth.status_code, status.HTTP_401_UNAUTHORIZED
        )


class ItemAPITests(BaseAPITestCase):  # Herda da Base
    """ Testes para os endpoints de Itens. """
    # Type hints
    user_a: CustomUser
    user_b: CustomUser
    token_a: Token
    token_b: Token
    item_pa: Item
    item_pb: Item
    item_ra: Item
    item_rb: Item
    public_list_url: str
    restricted_list_url: str

    @classmethod
    def setUpTestData(cls) -> None:
        """ Cria usuários e alguns itens. """
        cls.public_list_url = reverse('capy:public-item-list')
        cls.restricted_list_url = reverse('capy:restricted-item-list')
        # User A (Confirmado)
        cls.user_a = create_test_user(
            'itemuser_a', 'item_a@example.com',
            'UserAPassword1', confirmed=True
        )
        # User B (Não Confirmado)
        cls.user_b = create_test_user(
            'itemuser_b', 'item_b@example.com',
            'UserBPassword1', confirmed=False
        )
        # Itens (Reduzido para 1 público e 1 restrito por user)
        cls.item_pa = Item.objects.create(
            owner=cls.user_a, title="Public A Search", is_public=True
        )
        cls.item_pb = Item.objects.create(
            owner=cls.user_b, title="Public B Search", is_public=True
        )
        cls.item_ra = Item.objects.create(
            owner=cls.user_a, title="Restricted A", is_public=False
        )
        cls.item_rb = Item.objects.create(
            owner=cls.user_b, title="Restricted B", is_public=False
        )

    def setUp(self) -> None:
        """ Obtém tokens. """
        self.token_a = self._get_token_for_user(self.user_a, 'UserAPassword1')
        self.token_b = self._get_token_for_user(self.user_b, 'UserBPassword1')

    def test_public_list_access_and_content(self) -> None:
        """ Testa listagem pública (sem auth) e conteúdo básico. """
        response = self.client.get(self.public_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Apenas item_pa e item_pb
        self.assertEqual(response.data['count'], 2)
        titles = [item['title'] for item in response.data['results']]
        self.assertCountEqual(titles, [self.item_pa.title, self.item_pb.title])

    def test_public_list_filters_search_order(self) -> None:
        """ Testa filtros, busca e ordenação na lista pública. """
        # Filtro Owner A
        url_owner_a = f"{self.public_list_url}?owner={self.user_a.id}"
        response_owner_a = self.client.get(url_owner_a)
        self.assertEqual(response_owner_a.data['count'], 1)
        self.assertEqual(
            response_owner_a.data['results'][0]['title'], self.item_pa.title
        )

        # Busca
        url_search = f"{self.public_list_url}?search=Search"
        response_search = self.client.get(url_search)
        # Ambos têm 'Search'
        self.assertEqual(response_search.data['count'], 2)

        # Ordenação
        url_order = f"{self.public_list_url}?ordering=title"
        response_order = self.client.get(url_order)
        titles_ordered = [
            item['title'] for item in response_order.data['results']
        ]
        # Ordem A->B
        self.assertEqual(titles_ordered,
                         [self.item_pa.title, self.item_pb.title])

    def test_item_creation(self) -> None:
        """ Testa criação de item (sucesso autenticado,
        falha não autenticado). """
        # Falha sem auth
        item_data = {'title': 'Fail Item'}
        response_unauth = self.client.post(
            self.public_list_url, item_data, format='json'
        )
        self.assertEqual(
            response_unauth.status_code, status.HTTP_401_UNAUTHORIZED
        )

        # Sucesso com auth
        self._authenticate_client(self.token_a)
        item_data_ok = {'title': 'New Item By A'}
        response_ok = self.client.post(
            self.public_list_url, item_data_ok, format='json'
        )
        self.assertEqual(response_ok.status_code, status.HTTP_201_CREATED)
        item_exists = Item.objects.filter(
            title='New Item By A', owner=self.user_a
        ).exists()
        self.assertTrue(item_exists)

    def test_restricted_list_permissions(self) -> None:
        """ Testa permissões de acesso à lista restrita. """
        # Falha sem auth
        self._clear_authentication()
        response_unauth = self.client.get(self.restricted_list_url)
        self.assertEqual(response_unauth.status_code,
                         status.HTTP_401_UNAUTHORIZED)

        # Falha com auth mas email não confirmado
        self._authenticate_client(self.token_b)  # User B não confirmado
        response_unconf = self.client.get(self.restricted_list_url)
        self.assertEqual(
            response_unconf.status_code, status.HTTP_403_FORBIDDEN
        )

        # Sucesso com auth e email confirmado
        self._authenticate_client(self.token_a)  # User A confirmado
        response_ok = self.client.get(self.restricted_list_url)
        self.assertEqual(response_ok.status_code, status.HTTP_200_OK)
        # item_ra, item_rb
        self.assertEqual(response_ok.data['count'], 2)

    def test_restricted_list_filtering(self) -> None:
        """ Testa filtros na lista restrita. """
        self._authenticate_client(self.token_a)  # User A confirmado
        # Filtro por dono (User B)
        url_owner_b = f"{self.restricted_list_url}?owner={self.user_b.id}"
        response_owner_b = self.client.get(url_owner_b)
        self.assertEqual(response_owner_b.data['count'], 1)
        self.assertEqual(
            response_owner_b.data['results'][0]['title'], self.item_rb.title
        )


class EmailConfirmationAPITests(BaseAPITestCase):  # Herda da Base
    """ Testes para confirmação de e-mail. """
    # Type hints
    user_unconfirmed: CustomUser
    user_confirmed: CustomUser
    token_unconfirmed: Token
    token_confirmed: Token
    request_url: str
    validate_url: str
    password: str

    @classmethod
    def setUpTestData(cls) -> None:
        cls.password = 'TestPassword123'
        cls.user_unconfirmed = create_test_user(
            'unconfirmed_user', 'unconfirmed@example.com', cls.password,
            confirmed=False
        )
        cls.user_confirmed = create_test_user(
            'confirmed_user', 'confirmed@example.com', cls.password,
            confirmed=True
        )
        cls.request_url = reverse('capy:request-confirmation-email')
        cls.validate_url = reverse('capy:validate-confirmation-email')

    def setUp(self) -> None:
        """ Obtém tokens. """
        self.token_unconfirmed = self._get_token_for_user(
            self.user_unconfirmed, self.password
        )
        self.token_confirmed = self._get_token_for_user(
            self.user_confirmed, self.password)

    # --- Testes para Request Confirmation ---
    # (test_request_token_success_unconfirmed_user,
    #  test_request_token_fail_confirmed_user,
    #  test_request_token_fail_unauthenticated já existem e estão corretos)

    # --- Testes SEPARADOS para Validate Confirmation ---

    def test_validate_token_success(self) -> None:
        """ Testa validação bem-sucedida com token correto. """
        self._authenticate_client(self.token_unconfirmed)
        # 1. Solicita/Gera token
        req_resp = self.client.post(self.request_url)
        self.assertEqual(req_resp.status_code, status.HTTP_200_OK)
        confirmation_token = req_resp.data['token']

        # 2. Valida
        validation_data = {'token': confirmation_token}
        response = self.client.post(
            self.validate_url, validation_data, format='json'
        )

        # 3. Verifica
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(
            'confirmado com sucesso', response.data.get('message', '')
        )
        self.user_unconfirmed.refresh_from_db()
        self.assertTrue(self.user_unconfirmed.email_confirmed)
        self.assertIsNone(self.user_unconfirmed.confirmation_token)

    def test_validate_token_fail_wrong_token(self) -> None:
        """ Testa falha na validação com token errado/inválido. """
        # 1. Garante que usuário não está confirmado e TEM um token pendente
        self.user_unconfirmed.email_confirmed = False  # Garante estado inicial
        self.user_unconfirmed.confirmation_token = uuid.uuid4()
        self.user_unconfirmed.token_created_at = timezone.now()
        self.user_unconfirmed.save()

        # 2. Tenta validar com um token diferente
        self._authenticate_client(self.token_unconfirmed)
        wrong_token = uuid.uuid4()
        validation_data = {'token': str(wrong_token)}
        response = self.client.post(
            self.validate_url, validation_data, format='json'
        )

        # 3. Verifica
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('inválido', response.data.get('error', ''))
        self.user_unconfirmed.refresh_from_db()
        # Não deve ter confirmado
        self.assertFalse(self.user_unconfirmed.email_confirmed)

    def test_validate_token_info_already_confirmed(self) -> None:
        """ Testa comportamento ao tentar validar email já confirmado. """
        self._authenticate_client(self.token_confirmed)
        # Tenta validar com qualquer token
        validation_data = {'token': str(uuid.uuid4())}
        response = self.client.post(
            self.validate_url, validation_data, format='json'
        )

        # View retorna 200 OK com mensagem informativa
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(
            'confirmado anteriormente', response.data.get('message', '')
        )
        self.user_confirmed.refresh_from_db()
        # Continua confirmado
        self.assertTrue(self.user_confirmed.email_confirmed)

    def test_validate_token_fail_no_pending_token(self) -> None:
        """ Testa falha ao validar sem token pendente no usuário. """
        # Garante que usuário não está confirmado e NÃO tem token pendente
        self.user_unconfirmed.email_confirmed = False  # Garante estado inicial
        self.user_unconfirmed.confirmation_token = None
        self.user_unconfirmed.token_created_at = None
        self.user_unconfirmed.save()

        self._authenticate_client(self.token_unconfirmed)
        validation_data = {'token': str(uuid.uuid4())}
        response = self.client.post(
            self.validate_url, validation_data, format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Nenhum processo', response.data.get('error', ''))

    def test_validate_token_fail_unauthenticated(self) -> None:
        """ Testa falha na validação sem autenticação. """
        self._clear_authentication()  # Garante não autenticado
        validation_data = {'token': str(uuid.uuid4())}
        response = self.client.post(
            self.validate_url, validation_data, format='json'
        )
        self.assertEqual(
            response.status_code, status.HTTP_401_UNAUTHORIZED
        )
