# capy/tests.py

import uuid
# from datetime import timedelta # Unused import removed
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token

from .models import CustomUser, Item


class UserRegistrationLoginTests(APITestCase):
    """
    Testes para os endpoints de registro e obtenção de token (login).
    """

    def setUp(self) -> None:
        """
        Configuração inicial executada antes de cada teste nesta classe.
        """
        self.register_url = reverse('capy:register')
        self.token_url = reverse('capy:api_token_auth')

        self.user_data = {
            "username": "testregistrar",
            "email": "testregistrar@example.com",
            "first_name": "Test",
            "last_name": "Registrar",
            "password": "StrongPassword123",
            "password2": "StrongPassword123"
        }
        # Criar um usuário padrão para testes de login
        self.test_user_email = 'logintest@example.com'
        self.test_user_username = 'logintestuser'
        self.test_user_password = 'LoginPassword123'
        self.user = CustomUser.objects.create_user(
            username=self.test_user_username,
            email=self.test_user_email,
            password=self.test_user_password,
            first_name='Login',
            last_name='Test'
        )

    def test_user_registration_success(self) -> None:
        """
        Verifica se um novo usuário pode ser registrado com sucesso via API.
        """
        response = self.client.post(
            self.register_url, self.user_data, format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(CustomUser.objects.count(), 2)
        new_user = CustomUser.objects.get(email=self.user_data['email'])
        self.assertEqual(new_user.email, self.user_data['email'])
        self.assertEqual(new_user.username, self.user_data['username'])
        self.assertFalse(new_user.email_confirmed)
        self.assertTrue(new_user.has_usable_password())

        # Verifica o Corpo da Resposta JSON
        self.assertIn('id', response.data)
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'], self.user_data['email'])
        self.assertIn('email_confirmed', response.data)
        self.assertEqual(response.data['email_confirmed'], False)
        self.assertNotIn('password', response.data)

    def test_user_registration_fail_duplicate_email(self) -> None:
        """
        Verifica se o registro falha se o email já existir.
        """
        self.assertEqual(CustomUser.objects.count(), 1)
        duplicate_email_data = self.user_data.copy()
        duplicate_email_data['email'] = self.test_user_email
        duplicate_email_data['username'] = 'newuser'

        response = self.client.post(
            self.register_url, duplicate_email_data, format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        self.assertEqual(CustomUser.objects.count(), 1)

    def test_user_registration_fail_duplicate_username(self) -> None:
        """
        Verifica se o registro falha se o username já existir.
        """
        self.assertEqual(CustomUser.objects.count(), 1)
        duplicate_username_data = self.user_data.copy()
        duplicate_username_data['username'] = self.test_user_username
        duplicate_username_data['email'] = 'newemail@example.com'

        response = self.client.post(
            self.register_url, duplicate_username_data, format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)
        self.assertEqual(CustomUser.objects.count(), 1)

    def test_user_registration_fail_password_mismatch(self) -> None:
        """
        Verifica se o registro falha se as senhas não coincidirem.
        """
        mismatch_password_data = self.user_data.copy()
        mismatch_password_data['password2'] = 'DifferentPassword123'

        response = self.client.post(
            self.register_url, mismatch_password_data, format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        error_keys = list(response.data.keys())
        self.assertIn('password2', error_keys)
        self.assertEqual(CustomUser.objects.count(), 1)

    def test_token_obtain_success(self) -> None:
        """
        Verifica se um usuário registrado consegue obter um token.
        """
        login_data = {
            'username': self.test_user_email,
            'password': self.test_user_password
        }
        response = self.client.post(self.token_url, login_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertTrue(response.data['token'])

    def test_token_obtain_fail_wrong_password(self) -> None:
        """
        Verifica se a obtenção de token falha com senha incorreta.
        """
        login_data = {
            'username': self.test_user_email,
            'password': 'WrongPassword'
        }
        response = self.client.post(self.token_url, login_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
        self.assertNotIn('token', response.data)

    def test_token_obtain_fail_nonexistent_user(self) -> None:
        """
        Verifica se a obtenção de token falha para um usuário que não existe.
        """
        login_data = {
            'username': 'nosuchuser@example.com',
            'password': 'SomePassword'
        }
        response = self.client.post(self.token_url, login_data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
        self.assertNotIn('token', response.data)


class ProfileAPITests(APITestCase):
    """
    Testes para o endpoint do perfil do usuário (/api/profile/).
    """
    user: CustomUser  # Type hint
    token: str        # Type hint

    def setUp(self) -> None:
        """
        Cria um usuário e obtém seu token para usar nos testes autenticados.
        """
        self.password = 'TestPassword123'
        self.user = CustomUser.objects.create_user(
            username='profileuser',
            email='profile@example.com',
            password=self.password,
            first_name='Profile',
            last_name='Test'
        )
        self.profile_url = reverse('capy:profile')
        self.change_password_url = reverse('capy:change-password')

        token_url = reverse('capy:api_token_auth')
        response = self.client.post(
            token_url,
            {'username': self.user.email, 'password': self.password},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.token = response.data['token']
        # Set credentials for subsequent requests IN THIS TEST METHOD
        # It's safer to set it inside each test method that needs it.
        # self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def test_change_password_success(self) -> None:
        """ Verifica se a senha pode ser alterada com sucesso. """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token}')
        new_password = "NewSecurePassword456!"
        data = {
            "old_password": self.password,
            "new_password1": new_password,
            "new_password2": new_password
        }
        response = self.client.put(
            self.change_password_url, data, format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check specific message structure if needed
        self.assertEqual(response.data.get('message'),
                         "Password updated successfully")

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

        token_url = reverse('capy:api_token_auth')
        login_response = self.client.post(
            token_url,
            {'username': self.user.email, 'password': new_password},
            format='json'
        )
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)

    def test_change_password_fail_wrong_old_password(self) -> None:
        """ Verifica se a alteração falha com senha antiga incorreta. """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token}')
        data = {
            "old_password": "WRONG_OLD_PASSWORD",
            "new_password1": "NewSecurePassword456!",
            "new_password2": "NewSecurePassword456!"
        }
        response = self.client.put(
            self.change_password_url, data, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('old_password', response.data)

    def test_change_password_fail_mismatched_new_password(self) -> None:
        """ Verifica se a alteração falha."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token}')
        data = {
            "old_password": self.password,
            "new_password1": "NewSecurePassword456!",
            "new_password2": "MISMATCHED_PASSWORD"
        }
        response = self.client.put(
            self.change_password_url, data, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Serializer raises for this field
        self.assertIn('new_password2', response.data)

    def test_change_password_fail_unauthenticated(self) -> None:
        """ Verifica se a alteração falha sem autenticação. """
        self.client.logout()  # Ensure client is logged out
        data = {
            "old_password": self.password,
            "new_password1": "NewSecurePassword456!",
            "new_password2": "NewSecurePassword456!"
        }
        response = self.client.put(
            self.change_password_url, data, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_profile_success(self) -> None:
        """
        Verifica se um usuário autenticado consegue visualizar seu perfil.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token}')
        response = self.client.get(self.profile_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user.email)
        self.assertEqual(response.data['username'], self.user.username)
        self.assertEqual(response.data['first_name'], self.user.first_name)
        self.assertEqual(response.data['id'], self.user.id)
        self.assertFalse(response.data['email_confirmed'])

    def test_get_profile_fail_unauthenticated(self) -> None:
        """
        Verifica se um usuário não autenticado recebe 401.
        """
        self.client.credentials()  # Clear credentials
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_profile_patch_success(self) -> None:
        """
        Verifica se um usuário autenticado consegue atualizar com PATCH.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token}')
        update_data = {'first_name': 'Profile Updated'}
        response = self.client.patch(
            self.profile_url, update_data, format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Profile Updated')

        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Profile Updated')

    def test_update_profile_fail_unauthenticated(self) -> None:
        """
        Verifica se um usuário não autenticado recebe 401 ao tentar atualizar.
        """
        self.client.credentials()  # Clear credentials
        update_data = {'first_name': 'Failing Update'}
        response = self.client.patch(
            self.profile_url, update_data, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ItemAPITests(APITestCase):
    """
    Testes para os endpoints de Itens (/api/items/public/ e
    /api/items/restricted/).
    """
    # Type hints for class variables set in setUpTestData
    user_a: CustomUser
    user_b: CustomUser
    item_pa1: Item
    item_pa2: Item
    item_pb1: Item
    item_ra1: Item
    item_rb1: Item
    public_list_url: str
    restricted_list_url: str
    user_a_pw: str
    user_b_pw: str
    # Type hints for instance variables set in setUp
    token_a: Token
    token_b: Token

    @classmethod
    def setUpTestData(cls) -> None:
        """
        Configuração executada uma vez para a classe toda.
        """
        cls.public_list_url = reverse('capy:public-item-list')
        cls.restricted_list_url = reverse('capy:restricted-item-list')
        cls.user_a_pw = 'UserAPassword1'
        cls.user_a = CustomUser.objects.create_user(
            username='itemuser_a', email='item_a@example.com',
            password=cls.user_a_pw, first_name='Item', last_name='UserA'
        )
        cls.user_a.email_confirmed = True
        cls.user_a.save()
        cls.user_b_pw = 'UserBPassword1'
        cls.user_b = CustomUser.objects.create_user(
            username='itemuser_b', email='item_b@example.com',
            password=cls.user_b_pw, first_name='Item', last_name='UserB'
        )
        # Itens
        cls.item_pa1 = Item.objects.create(
            owner=cls.user_a, title="Public A1", description="Desc PA1",
            is_public=True
        )
        cls.item_pa2 = Item.objects.create(
            owner=cls.user_a, title="Public A2 Search", description="Desc PA2",
            is_public=True
        )
        cls.item_pb1 = Item.objects.create(
            owner=cls.user_b, title="Public B1 Search", description="Desc PB1",
            is_public=True
        )
        cls.item_ra1 = Item.objects.create(
            owner=cls.user_a, title="Restricted A1", description="Desc RA1",
            is_public=False
        )
        cls.item_rb1 = Item.objects.create(
            owner=cls.user_b, title="Restricted B1", description="Desc RB1",
            is_public=False
        )

    def setUp(self) -> None:
        """ Obtém tokens para os usuários antes de cada teste """
        self.token_a, _ = Token.objects.get_or_create(user=self.user_a)
        self.token_b, _ = Token.objects.get_or_create(user=self.user_b)

    def test_list_public_items_unauthenticated(self) -> None:
        """ Verifica lista pública acessível e retorna itens corretos. """
        response = self.client.get(self.public_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 3)
        results_titles = [item['title'] for item in response.data['results']]
        # Use assertCountEqual for lists
        self.assertCountEqual(
            results_titles,
            [self.item_pa1.title, self.item_pa2.title, self.item_pb1.title]
        )
        self.assertNotIn(self.item_ra1.title, results_titles)

    def test_create_public_item_authenticated(self) -> None:
        """ Verifica se um usuário autenticado pode criar um item público. """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_a.key}')
        item_data = {
            'title': 'New Public Item A', 'description': 'Created in test'
        }
        response = self.client.post(
            self.public_list_url, item_data, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Count depends on how many tests ran before,
        # better to check existence
        self.assertTrue(
            Item.objects.filter(title='New Public Item A').exists()
        )
        new_item = Item.objects.get(title='New Public Item A')
        self.assertEqual(new_item.owner, self.user_a)
        self.assertTrue(new_item.is_public)

    def test_create_public_item_unauthenticated(self) -> None:
        """ Verifica se criar item falha sem autenticação. """
        item_data = {
            'title': 'Fail Item', 'description': 'Should not be created'
        }
        response = self.client.post(
            self.public_list_url, item_data, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_list_restricted_items_success_confirmed_user(self) -> None:
        """ Verifica se usuário confirmado acessa itens restritos. """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_a.key}')
        response = self.client.get(self.restricted_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)
        results_titles = [item['title'] for item in response.data['results']]
        self.assertCountEqual(
            results_titles,
            [self.item_ra1.title, self.item_rb1.title]
        )
        self.assertNotIn(self.item_pa1.title, results_titles)

    def test_list_restricted_items_fail_unconfirmed_user(self) -> None:
        """ Verifica se usuário NÃO confirmado é barrado. """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_b.key}')
        response = self.client.get(self.restricted_list_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn(
            'endereço de e-mail precisa ser confirmado', str(response.data)
        )

    def test_list_restricted_items_fail_unauthenticated(self) -> None:
        """ Verifica se usuário não autenticado é barrado. """
        self.client.credentials()  # Clear credentials
        response = self.client.get(self.restricted_list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_restricted_list_filters_ordering_search(self) -> None:
        """ Testa filtros/ordenação/busca na lista restrita. """
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token_a.key}')
        response = self.client.get(
            self.restricted_list_url + f'?owner={self.user_b.id}'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['title'],
                         self.item_rb1.title)


class EmailConfirmationAPITests(APITestCase):
    """
    Testes para os endpoints de solicitação
    e validação de confirmação de e-mail.
    """
    # Type hints for class variables
    user_unconfirmed: CustomUser
    user_confirmed: CustomUser
    request_url: str
    validate_url: str
    password: str
    # Type hints for instance variables
    token_unconfirmed: Token
    token_confirmed: Token

    @classmethod
    def setUpTestData(cls) -> None:
        cls.password = 'TestPassword123'
        cls.user_unconfirmed = CustomUser.objects.create_user(
            username='unconfirmed_user',
            email='unconfirmed@example.com',
            password=cls.password,
            first_name='Unconfirmed',
            last_name='Test',
            email_confirmed=False
        )
        cls.user_confirmed = CustomUser.objects.create_user(
            username='confirmed_user',
            email='confirmed@example.com',
            password=cls.password,
            first_name='Confirmed',
            last_name='Test',
            email_confirmed=True
        )
        cls.request_url = reverse('capy:request-confirmation-email')
        cls.validate_url = reverse('capy:validate-confirmation-email')

    def setUp(self) -> None:
        """ Obtém tokens para os usuários """
        self.token_unconfirmed, _ = Token.objects.get_or_create(
            user=self.user_unconfirmed
        )
        self.token_confirmed, _ = Token.objects.get_or_create(
            user=self.user_confirmed
        )

    def test_request_token_success_unconfirmed_user(self) -> None:
        """ Verifica se usuário não confirmado pode solicitar token. """
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Token {self.token_unconfirmed.key}'
        )
        response = self.client.post(self.request_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.user_unconfirmed.refresh_from_db()
        self.assertIsNotNone(self.user_unconfirmed.confirmation_token)
        self.assertIsNotNone(self.user_unconfirmed.token_created_at)

    def test_request_token_fail_confirmed_user(self) -> None:
        """ Verifica se usuário já confirmado não pode solicitar token. """
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Token {self.token_confirmed.key}'
        )
        response = self.client.post(self.request_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('confirmado', response.data.get('message', ''))

    def test_request_token_fail_unauthenticated(self) -> None:
        """ Verifica falha ao solicitar token sem autenticação. """
        self.client.credentials()  # Ensure no auth
        response = self.client.post(self.request_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_validate_token_success(self) -> None:
        """ Verifica validação bem-sucedida com token correto. """
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Token {self.token_unconfirmed.key}'
        )
        request_response = self.client.post(self.request_url)
        self.assertEqual(request_response.status_code, status.HTTP_200_OK)
        confirmation_token = request_response.data['token']

        validation_data = {'token': confirmation_token}
        response = self.client.post(
            self.validate_url, validation_data, format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(
            'confirmado com sucesso', response.data.get('message', '')
        )

        self.user_unconfirmed.refresh_from_db()
        self.assertTrue(self.user_unconfirmed.email_confirmed)
        self.assertIsNone(self.user_unconfirmed.confirmation_token)
        self.assertIsNone(self.user_unconfirmed.token_created_at)

    def test_validate_token_fail_wrong_token(self) -> None:
        """ Verifica falha na validação com token UUID inválido/errado. """
        self.user_unconfirmed.confirmation_token = uuid.uuid4()
        self.user_unconfirmed.token_created_at = timezone.now()
        self.user_unconfirmed.save()

        self.client.credentials(
            HTTP_AUTHORIZATION=f'Token {self.token_unconfirmed.key}'
        )
        wrong_token = uuid.uuid4()
        validation_data = {'token': str(wrong_token)}
        response = self.client.post(
            self.validate_url, validation_data, format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('inválido', response.data.get('error', ''))
        self.user_unconfirmed.refresh_from_db()
        self.assertFalse(self.user_unconfirmed.email_confirmed)

    def test_validate_token_fail_already_confirmed(self) -> None:
        """ Verifica comportamento ao tentar validar email já confirmado. """
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Token {self.token_confirmed.key}'
        )
        validation_data = {'token': str(uuid.uuid4())}
        response = self.client.post(
            self.validate_url, validation_data, format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('confirmado anteriormente',
                      response.data.get('message', ''))
        self.user_confirmed.refresh_from_db()
        self.assertTrue(self.user_confirmed.email_confirmed)

    def test_validate_token_fail_no_pending_token(self) -> None:
        """ Verifica falha ao tentar validar
        sem ter solicitado um token antes. """
        self.user_unconfirmed.confirmation_token = None
        self.user_unconfirmed.token_created_at = None
        self.user_unconfirmed.save()

        self.client.credentials(
            HTTP_AUTHORIZATION=f'Token {self.token_unconfirmed.key}'
        )
        validation_data = {'token': str(uuid.uuid4())}
        response = self.client.post(
            self.validate_url, validation_data, format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn(
            'Nenhum processo de confirmação pendente',
            response.data.get('error', '')
        )

    def test_validate_token_fail_unauthenticated(self) -> None:
        """ Verifica falha na validação sem autenticação. """
        self.client.credentials()  # Ensure no auth
        validation_data = {'token': str(uuid.uuid4())}
        response = self.client.post(
            self.validate_url, validation_data, format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
