# capy/tests.py

from django.urls import reverse  # Para obter URLs a partir dos nomes
from rest_framework import status
from rest_framework.test import APITestCase
# Importa o modelo de usuário para verificar o banco
from .models import CustomUser, Item
from rest_framework.authtoken.models import Token


# Vamos agrupar testes por funcionalidade em classes
class UserRegistrationLoginTests(APITestCase):
    """
    Testes para os endpoints de registro e obtenção de token (login).
    """

    def setUp(self):
        """
        Configuração inicial executada antes de cada teste nesta classe.
        """
        # URLs usadas nos testes
        # Obtém '/api/register/' a partir do nome
        self.register_url = reverse('capy:register')
        self.token_url = reverse('capy:api_token_auth')

        # Dados de exemplo para um novo usuário
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

    def test_user_registration_success(self):
        """
        Verifica se um novo usuário pode ser registrado com sucesso via API.
        """
        response = self.client.post(self.register_url, self.user_data,
                                    format='json')

        # 1. Verifica o Status Code da Resposta
        # Esperamos 201 Created para um registro bem-sucedido
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # 2. Verifica se o usuário foi realmente criado no banco de dados
        # Deve existir um usuário a mais após este teste
        self.assertEqual(CustomUser.objects.count(), 2)
        # Pega o usuário criado (o segundo, pois o primeiro foi no setUp)
        new_user = CustomUser.objects.get(email=self.user_data['email'])
        # Verifica se os dados básicos foram salvos corretamente
        self.assertEqual(new_user.email, self.user_data['email'])
        self.assertEqual(new_user.username, self.user_data['username'])
        # Verifica se o email_confirmed começa como False
        self.assertFalse(new_user.email_confirmed)
        # Verifica se a senha foi definida
        self.assertTrue(new_user.has_usable_password())

        # 3. Verifica o Corpo da Resposta JSON
        # A resposta deve conter os dados formatados pelo UserSerializer
        self.assertIn('id', response.data)
        # Verifica se o ID está na resposta
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'], self.user_data['email'])
        self.assertIn('email_confirmed', response.data)
        self.assertEqual(response.data['email_confirmed'], False)
        # Verifica se a senha NÃO está na resposta
        self.assertNotIn('password', response.data)

    def test_user_registration_fail_duplicate_email(self):
        """
        Verifica se o registro falha se o email já existir.
        """
        # O usuário 'logintest@example.com' já existe do setUp
        self.assertEqual(CustomUser.objects.count(), 1)

        # 2. Preparar dados para o novo usuário com email duplicado
        # Copia os dados base do setUp
        duplicate_email_data = self.user_data.copy()
        # Usa o email existente
        duplicate_email_data['email'] = self.test_user_email
        duplicate_email_data['username'] = 'newuser'  # Username diferente

        # 3. Tentar registrar com email duplicado
        response = self.client.post(self.register_url, duplicate_email_data,
                                    format='json')

        # 4. Verificar o resultado
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Verifica se o erro está associado ao campo 'email'
        self.assertIn('email', response.data)
        # Garante que nenhum novo usuário foi criado
        self.assertEqual(CustomUser.objects.count(), 1)

    def test_user_registration_fail_duplicate_username(self):
        """
        Verifica se o registro falha se o username já existir.
        """
        # O usuário 'logintestuser' já existe do setUp
        self.assertEqual(CustomUser.objects.count(), 1)

        # 2. Preparar dados com username duplicado
        duplicate_username_data = self.user_data.copy()
        # Usa username existente
        duplicate_username_data['username'] = self.test_user_username
        # Email diferente
        duplicate_username_data['email'] = 'newemail@example.com'

        # 3. Tentar registrar com username duplicado
        response = self.client.post(self.register_url,
                                    duplicate_username_data, format='json')

        # 4. Verificar o resultado
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)
        self.assertEqual(CustomUser.objects.count(), 1)

    def test_user_registration_fail_password_mismatch(self):
        """
        Verifica se o registro falha se as senhas não coincidirem.
        """
        # 1. Preparar dados com senhas diferentes
        mismatch_password_data = self.user_data.copy()
        mismatch_password_data['password2'] = 'DifferentPassword123'

        # 2. Tentar registrar
        response = self.client.post(self.register_url, mismatch_password_data,
                                    format='json')

        # 3. Verificar o resultado
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # A validação no RegisterSerializer associa o erro a 'password'
        # ou 'password2'. Checar a chave exata pode depender da implementação.
        error_keys = list(response.data.keys())
        self.assertTrue('password' in error_keys or 'password2' in error_keys)
        # Garante que nenhum novo usuário foi criado
        self.assertEqual(CustomUser.objects.count(), 1)

    def test_user_registration_fail_missing_field(self):
        """
        Verifica se o registro falha se um campo obrigatório faltar.
        """
        # 1. Preparar dados sem 'first_name'
        missing_field_data = self.user_data.copy()
        del missing_field_data['first_name']

        # 2. Tentar registrar
        response = self.client.post(self.register_url, missing_field_data,
                                    format='json')

        # 3. Verificar o resultado
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Verifica se o erro está no campo 'first_name'
        self.assertIn('first_name', response.data)
        # Garante que nenhum novo usuário foi criado
        self.assertEqual(CustomUser.objects.count(), 1)

    def test_token_obtain_success(self):
        """
        Verifica se um usuário registrado consegue obter um token.
        """
        # Dados para fazer login (lembre-se: username=email)
        login_data = {
            # Usa o email do usuário criado no setUp
            'username': self.test_user_email,
            'password': self.test_user_password
        }
        # Faz a requisição POST para obter o token
        response = self.client.post(self.token_url, login_data, format='json')

        # Verificar sucesso
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verificar se a resposta contém a chave 'token'
        self.assertIn('token', response.data)
        # Verificar se o valor do token não está vazio
        self.assertTrue(response.data['token'])

    def test_token_obtain_fail_wrong_password(self):
        """
        Verifica se a obtenção de token falha com senha incorreta.
        """
        login_data = {
            'username': self.test_user_email,
            'password': 'WrongPassword'  # Senha incorreta
        }
        response = self.client.post(self.token_url, login_data, format='json')

        # Verificar falha
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # A view obtain_auth_token retorna erro em 'non_field_errors'
        self.assertIn('non_field_errors', response.data)
        # Verificar que 'token' NÃO está na resposta
        self.assertNotIn('token', response.data)

    def test_token_obtain_fail_nonexistent_user(self):
        """
        Verifica se a obtenção de token falha para um usuário que não existe.
        """
        login_data = {
            'username': 'nosuchuser@example.com',  # Email não registrado
            'password': 'SomePassword'
        }
        response = self.client.post(self.token_url, login_data, format='json')

        # Verificar falha
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)
        self.assertNotIn('token', response.data)


class ProfileAPITests(APITestCase):
    """
    Testes para o endpoint do perfil do usuário (/api/profile/).
    """

    def setUp(self):
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

        # Obter o token para o usuário criado
        token_url = reverse('capy:api_token_auth')
        response = self.client.post(
            token_url,
            {'username': self.user.email, 'password': self.password},
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.token = response.data['token']
        # Define o cabeçalho de autorização para as próximas requisições
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

    def test_get_profile_success(self):
        """
        Verifica se um usuário autenticado consegue visualizar seu perfil.
        """
        response = self.client.get(self.profile_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verifica se os dados retornados correspondem ao usuário
        self.assertEqual(response.data['email'], self.user.email)
        self.assertEqual(response.data['username'], self.user.username)
        self.assertEqual(response.data['first_name'], self.user.first_name)
        self.assertEqual(response.data['id'], self.user.id)
        # Verifica estado inicial
        self.assertFalse(response.data['email_confirmed'])

    def test_get_profile_fail_unauthenticated(self):
        """
        Verifica se um usuário não autenticado recebe 401.
        """
        self.client.credentials()  # Limpa as credenciais
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_profile_patch_success(self):
        """
        Verifica se um usuário autenticado consegue atualizar com PATCH.
        """
        # Dados para atualização parcial
        update_data = {'first_name': 'Profile Updated'}
        response = self.client.patch(self.profile_url, update_data,
                                     format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verifica se a resposta já contém o dado atualizado
        self.assertEqual(response.data['first_name'], 'Profile Updated')

        # Verifica também se o dado foi realmente salvo no banco
        # Recarrega o objeto self.user do banco
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Profile Updated')

    def test_update_profile_put_success(self):
        """
        Verifica se um usuário autenticado consegue atualizar com PUT.
        Lembre-se: PUT geralmente requer todos os campos não read-only.
        """
        # Dados para atualização completa (Email e Username não podem mudar)
        update_data = {
            'first_name': 'Profile PUT',
            'last_name': 'Test PUT',
            'username': self.user.username,
            'email': self.user.email,
            # profile_image é opcional, não precisa incluir se não mudar
        }
        response = self.client.put(self.profile_url, update_data,
                                   format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['first_name'], 'Profile PUT')
        self.assertEqual(response.data['last_name'], 'Test PUT')

        # Verificar banco
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Profile PUT')
        self.assertEqual(self.user.last_name, 'Test PUT')

    def test_update_profile_fail_unauthenticated(self):
        """
        Verifica se um usuário não autenticado recebe 401 ao tentar atualizar.
        """
        self.client.credentials()  # Limpa as credenciais
        update_data = {'first_name': 'Failing Update'}
        response = self.client.patch(self.profile_url, update_data,
                                     format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ItemAPITests(APITestCase):
    """
    Testes para os endpoints de Itens (/api/items/public/ e 
    /api/items/restricted/).
    """

    @classmethod
    def setUpTestData(cls):
        """
        Configuração executada uma vez para a classe toda.
        Cria usuários e itens iniciais para os testes.
        """
        # URLs
        cls.public_list_url = reverse('capy:public-item-list')
        cls.restricted_list_url = reverse('capy:restricted-item-list')

        # Usuário A (será confirmado)
        cls.user_a_pw = 'UserAPassword1'
        cls.user_a = CustomUser.objects.create_user(
            username='itemuser_a', email='item_a@example.com',
            password=cls.user_a_pw, first_name='Item', last_name='UserA'
        )
        # Confirma o email do Usuário A manualmente
        cls.user_a.email_confirmed = True
        cls.user_a.save()

        # Usuário B (NÃO será confirmado)
        cls.user_b_pw = 'UserBPassword1'
        cls.user_b = CustomUser.objects.create_user(
            username='itemuser_b', email='item_b@example.com',
            password=cls.user_b_pw, first_name='Item', last_name='UserB'
        )

        # Itens de Teste
        # Públicos
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
        # Restritos
        cls.item_ra1 = Item.objects.create(
            owner=cls.user_a, title="Restricted A1", description="Desc RA1",
            is_public=False
        )
        cls.item_rb1 = Item.objects.create(
            owner=cls.user_b, title="Restricted B1", description="Desc RB1",
            is_public=False
        )

    def setUp(self):
        """ Obtém tokens para os usuários antes de cada teste """
        # Usar Token.objects.get_or_create
        self.token_a, _ = Token.objects.get_or_create(user=self.user_a)
        self.token_b, _ = Token.objects.get_or_create(user=self.user_b)

    # --- Testes para /api/items/public/ ---

    def test_list_public_items_unauthenticated(self):
        """ Verifica lista pública acessível e retorna itens corretos. """
        response = self.client.get(self.public_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verifica se apenas os itens públicos estão na lista
        self.assertEqual(response.data['count'], 3)  # PA1, PA2, PB1
        results_titles = [item['title'] for item in response.data['results']]
        self.assertIn(self.item_pa1.title, results_titles)
        self.assertIn(self.item_pa2.title, results_titles)
        self.assertIn(self.item_pb1.title, results_titles)
        # Garante que restrito não aparece
        self.assertNotIn(self.item_ra1.title, results_titles)

    def test_create_public_item_authenticated(self):
        """ Verifica se um usuário autenticado pode criar um item público. """
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token_a.key)
        item_data = {
            'title': 'New Public Item A', 'description': 'Created in test'
        }
        response = self.client.post(self.public_list_url, item_data,
                                    format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Item.objects.count(), 6)  # 5 do setup + 1 novo
        new_item = Item.objects.get(title='New Public Item A')
        self.assertEqual(new_item.owner, self.user_a)
        self.assertTrue(new_item.is_public)

    def test_create_public_item_unauthenticated(self):
        """ Verifica se criar item falha sem autenticação. """
        item_data = {
            'title': 'Fail Item', 'description': 'Should not be created'
        }
        response = self.client.post(self.public_list_url, item_data,
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_public_list_search_filter(self):
        """ Testa o filtro de busca na lista pública. """
        response = self.client.get(self.public_list_url + '?search=Search')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)  # PA2, PB1
        results_titles = [item['title'] for item in response.data['results']]
        self.assertIn(self.item_pa2.title, results_titles)
        self.assertIn(self.item_pb1.title, results_titles)

    def test_public_list_owner_filter(self):
        """ Testa o filtro por dono na lista pública. """
        response = self.client.get(
            self.public_list_url + f'?owner={self.user_a.id}'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)  # PA1, PA2
        results_titles = [item['title'] for item in response.data['results']]
        self.assertIn(self.item_pa1.title, results_titles)
        self.assertIn(self.item_pa2.title, results_titles)

    def test_public_list_ordering(self):
        """ Testa a ordenação na lista pública. """
        # Ordem alfabética
        response = self.client.get(self.public_list_url + '?ordering=title')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results_titles = [item['title'] for item in response.data['results']]
        expected_order = [
            'Public A1', 'Public A2 Search', 'Public B1 Search'
        ]
        self.assertEqual(results_titles, expected_order)

    # --- Testes para /api/items/restricted/ ---

    def test_list_restricted_items_success_confirmed_user(self):
        """ Verifica se usuário confirmado acessa itens restritos. """
        # User A é confirmado
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token_a.key)
        response = self.client.get(self.restricted_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)  # RA1, RB1
        results_titles = [item['title'] for item in response.data['results']]
        self.assertIn(self.item_ra1.title, results_titles)
        self.assertIn(self.item_rb1.title, results_titles)
        # Garante que público não aparece
        self.assertNotIn(self.item_pa1.title, results_titles)

    def test_list_restricted_items_fail_unconfirmed_user(self):
        """ Verifica se usuário NÃO confirmado é barrado. """
        # User B NÃO é confirmado
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token_b.key)
        response = self.client.get(self.restricted_list_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        # Verifica a mensagem de erro da permissão IsEmailConfirmed
        self.assertIn(
            'endereço de e-mail precisa ser confirmado', str(response.data)
        )

    def test_list_restricted_items_fail_unauthenticated(self):
        """ Verifica se usuário não autenticado é barrado. """
        self.client.credentials()  # Limpa credenciais
        response = self.client.get(self.restricted_list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_restricted_list_filters_ordering_search(self):
        """ Testa filtros/ordenação/busca na lista restrita. """
        # User A confirmado
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token_a.key)

        # Teste de filtro por owner
        response = self.client.get(
            self.restricted_list_url + f'?owner={self.user_b.id}'
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['title'],
                         self.item_rb1.title)
