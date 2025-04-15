# capy/management/commands/seed_db.py

from django.core.management.base import BaseCommand
from django.db import transaction # Para garantir atomicidade
from capy.models import CustomUser, Item # Importa seus modelos

class Command(BaseCommand):
    help = 'Popula o banco de dados com dados iniciais de exemplo (Usuários e Itens)'

    @transaction.atomic # Garante que ou tudo é criado, ou nada é (se ocorrer erro)
    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING('Iniciando o processo de seed...'))

        # --- Verifica/Cria Usuários ---
        self.stdout.write('Criando/Verificando Usuários...')

        user1, created1 = CustomUser.objects.get_or_create(
            email='seeduser1@example.com',
            defaults={ # Valores a serem usados APENAS se o usuário for CRIADO
                'username': 'seeduser1',
                'first_name': 'Seed',
                'last_name': 'User One',
                'is_staff': False,
                'is_superuser': False,
                'email_confirmed': True  # Confirmar email para testar restrição
            }
        )
        # Define a senha apenas se o usuário foi criado para não resetar a cada run
        if created1:
            user1.set_password('SeedPass1!')
            user1.save()
            self.stdout.write(self.style.SUCCESS(f'Usuário "{user1.email}" criado.'))
        else:
            self.stdout.write(f'Usuário "{user1.email}" já existia.')

        user2, created2 = CustomUser.objects.get_or_create(
            email='seeduser2@example.com',
            defaults={
                'username': 'seeduser2',
                'first_name': 'Seed',
                'last_name': 'User Two',
                'email_confirmed': False # Deixar este não confirmado
            }
        )
        if created2:
            user2.set_password('SeedPass2@')
            user2.save()
            self.stdout.write(self.style.SUCCESS(f'Usuário "{user2.email}" criado.'))
        else:
             self.stdout.write(f'Usuário "{user2.email}" já existia.')

        # --- Verifica/Cria Itens ---
        self.stdout.write('Criando/Verificando Itens...')

        item1, created_i1 = Item.objects.get_or_create(
            title='Item Público Seed 1 (User 1)',
            defaults={'owner': user1, 'description': 'Descrição do item público 1.', 'is_public': True}
        )
        if created_i1: self.stdout.write(self.style.SUCCESS(f'Item "{item1.title}" criado.'))
        else: self.stdout.write(f'Item "{item1.title}" já existia.')

        item2, created_i2 = Item.objects.get_or_create(
            title='Item Restrito Seed 1 (User 1)',
            defaults={'owner': user1, 'description': 'Descrição do item restrito 1.', 'is_public': False}
        )
        if created_i2: self.stdout.write(self.style.SUCCESS(f'Item "{item2.title}" criado.'))
        else: self.stdout.write(f'Item "{item2.title}" já existia.')

        item3, created_i3 = Item.objects.get_or_create(
            title='Item Público Seed 2 (User 2)',
            defaults={'owner': user2, 'description': 'Descrição do item público 2.', 'is_public': True}
        )
        if created_i3: self.stdout.write(self.style.SUCCESS(f'Item "{item3.title}" criado.'))
        else: self.stdout.write(f'Item "{item3.title}" já existia.')

        item4, created_i4 = Item.objects.get_or_create(
            title='Item Restrito Seed 2 (User 2)',
            defaults={'owner': user2, 
                      'description': 'Descrição do item restrito 2.', 
                      'is_public': False}
        )
        if created_i4: 
            self.stdout.write(self.style.SUCCESS(f'Item "{item4.title}" criado.'))
        else: self.stdout.write(f'Item "{item4.title}" já existia.')

        self.stdout.write(self.style.SUCCESS('Processo de Seed concluído!'))