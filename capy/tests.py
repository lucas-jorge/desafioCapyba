from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model

from .models import Item

# Get the custom user model
CustomUser = get_user_model()


class AuthAndProfileTests(APITestCase):
    def setUp(self):
        # Common URLs
        self.register_url = reverse('capy:register')
        self.login_url = reverse('capy:api_token_auth')
        self.profile_url = reverse('capy:profile')
        # Common user data
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpassword123',
            'password2': 'testpassword123',
            'first_name': 'Test',
            'last_name': 'User',
        }

    def test_user_registration(self):
        """
        Ensure we can register a new user.
        """
        response = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(CustomUser.objects.count(), 1)
        user = CustomUser.objects.get()
        self.assertEqual(user.email, self.user_data['email'])
        # Check email_confirmed defaults to False
        self.assertFalse(user.email_confirmed)

    def test_user_login(self):
        """
        Ensure a registered user can log in and get a token.
        """
        # First, register the user
        self.client.post(self.register_url, self.user_data, format='json')
        # Attempt to login
        login_data = {
            'username': self.user_data['email'],  # Send email as username field
            'password': self.user_data['password']
        }
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        # Verify token exists for the user
        user = CustomUser.objects.get(email=self.user_data['email'])
        self.assertTrue(Token.objects.filter(user=user).exists())

    def test_profile_view_unauthenticated(self):
        """
        Ensure profile view requires authentication.
        """
        response = self.client.get(self.profile_url)
        # DRF defaults to 401 for IsAuthenticated without credentials
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_profile_view_authenticated(self):
        """
        Ensure authenticated user can view their profile.
        """
        # Register and login to get token
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {
            'username': self.user_data['email'], # Send email as username field
            'password': self.user_data['password']
        }
        login_response = self.client.post(self.login_url, login_data, format='json')
        token = login_response.data['token']

        # Access profile with token
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], self.user_data['email'])
        self.assertEqual(response.data['username'], self.user_data['username'])


class ItemTests(APITestCase):
    def setUp(self):
        # URLs
        self.item_list_url = reverse('capy:public-item-list')
        # User 1
        self.user1_data = {
            'username': 'user1', 'email': 'user1@example.com',
            'password': 'password1', 'password2': 'password1',
            'first_name': 'User', 'last_name': 'One'
        }
        self.user1 = CustomUser.objects.create_user(
            username=self.user1_data['username'],
            email=self.user1_data['email'],
            password=self.user1_data['password'],
            first_name=self.user1_data['first_name'],
            last_name=self.user1_data['last_name']
        )
        self.token1, _ = Token.objects.get_or_create(user=self.user1)
        # User 2
        self.user2_data = {
            'username': 'user2', 'email': 'user2@example.com',
            'password': 'password2', 'password2': 'password2',
            'first_name': 'User', 'last_name': 'Two'
        }
        self.user2 = CustomUser.objects.create_user(
            username=self.user2_data['username'],
            email=self.user2_data['email'],
            password=self.user2_data['password'],
            first_name=self.user2_data['first_name'],
            last_name=self.user2_data['last_name']
        )
        # Items
        self.item1 = Item.objects.create(
            owner=self.user1, title="Public Item 1", description="Test", is_public=True
        )
        self.item2 = Item.objects.create(
            owner=self.user1, title="Private Item 1", description="Test", is_public=False
        )
        self.item3 = Item.objects.create(
            owner=self.user2, title="Public Item 2", description="Test", is_public=True
        )

    def test_public_item_list_unauthenticated(self):
        """
        Ensure unauthenticated users can list public items.
        """
        response = self.client.get(self.item_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check pagination structure and count (should only list public items)
        self.assertIn('results', response.data)
        self.assertEqual(response.data['count'], 2)  # item1 and item3 are public
        # Check that only public items are returned
        titles = [item['title'] for item in response.data['results']]
        self.assertIn(self.item1.title, titles)
        self.assertIn(self.item3.title, titles)
        self.assertNotIn(self.item2.title, titles)  # Private item should not be listed

    def test_item_creation_unauthenticated(self):
        """
        Ensure unauthenticated users cannot create items.
        """
        item_data = {'title': 'New Item', 'description': 'Attempt'}
        response = self.client.post(self.item_list_url, item_data, format='json')
        # IsAuthenticatedOrReadOnly allows GET but requires auth for POST
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_item_creation_authenticated(self):
        """
        Ensure authenticated users can create items.
        """
        item_data = {
            'title': 'My New Item',
            'description': 'Created while logged in',
            'is_public': True
        }
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token1.key)
        response = self.client.post(self.item_list_url, item_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Item.objects.count(), 4)  # 3 from setup + 1 new
        new_item = Item.objects.get(title=item_data['title'])
        self.assertEqual(new_item.owner, self.user1)
        self.assertEqual(new_item.description, item_data['description'])
        self.assertTrue(new_item.is_public)

    def test_item_list_search(self):
        """ Test searching items by title """
        response = self.client.get(self.item_list_url + '?search=Public Item 1')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['title'], self.item1.title)

    def test_item_list_filter_owner(self):
        """ Test filtering items by owner id """
        response = self.client.get(self.item_list_url + f'?owner={self.user1.id}')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only return user1's *public* items
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['title'], self.item1.title)

    def test_item_list_ordering(self):
        """ Test ordering items by title """
        response = self.client.get(self.item_list_url + '?ordering=title')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)
        # Titles should be alphabetically ordered (Public Item 1, Public Item 2)
        self.assertEqual(response.data['results'][0]['title'], self.item1.title)
        self.assertEqual(response.data['results'][1]['title'], self.item3.title)

        # Test reverse ordering
        response = self.client.get(self.item_list_url + '?ordering=-title')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(response.data['results'][0]['title'], self.item3.title)
        self.assertEqual(response.data['results'][1]['title'], self.item1.title)
