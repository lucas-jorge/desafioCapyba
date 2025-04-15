# capy/admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Item

# Para customizar como o CustomUser aparece no Admin


class CustomUserAdmin(UserAdmin):
    # Mantém a maioria das configurações do UserAdmin padrão
    # Adiciona nossos campos customizados aos fieldsets
    # Copiamos os fieldsets padrão e adicionamos os nossos
    # Garantir que fieldsets não seja None e converter para lista
    _fieldsets = list(UserAdmin.fieldsets or ())
    _fieldsets.append(
        # Adiciona uma nova seção chamada 'Campos Customizados'
        ('Campos Customizados',
         {'fields': ('profile_image', 'email_confirmed')})
    )
    fieldsets = _fieldsets
    # Adiciona os campos customizados ao formulário de criação de usuário
    # Garantir que add_fieldsets não seja None e converter para lista
    _add_fieldsets = list(UserAdmin.add_fieldsets or ())
    _add_fieldsets.append(
        ('Campos Customizados',
         {'fields': ('profile_image', 'email_confirmed')})
    )
    add_fieldsets = _add_fieldsets

    # Adiciona colunas extras na listagem de usuários no admin
    list_display = (
        'email', 'username', 'first_name', 'last_name', 'is_staff',
        'email_confirmed'
    )
    # Adiciona 'email_confirmed' aos filtros laterais
    # Garantir que list_filter não seja None e converter para lista
    _list_filter = list(UserAdmin.list_filter or ())
    _list_filter.append('email_confirmed')
    # Convert back to tuple if needed, or keep as list
    list_filter = tuple(_list_filter)
    # Permite buscar por campos customizados (padrões já incluem email, etc.)
    # Garantir que search_fields não seja None
    # Não adicionar campos existentes
    search_fields = UserAdmin.search_fields or ()


# Registra o modelo Item no Admin (com configuração padrão)
@admin.register(Item)
class ItemAdmin(admin.ModelAdmin):
    # Mostra estes campos na listagem de itens
    list_display = ('title', 'owner_email_display', 'is_public', 'created_at')
    # Adiciona filtros laterais
    list_filter = ('is_public', 'owner', 'created_at')
    # Permite buscar por título, descrição e dados do dono
    search_fields = (
        'title', 'description', 'owner__email', 'owner__username'
    )
    # Define campos que são apenas para leitura no formulário de edição
    readonly_fields = ('created_at',)

    # Método para exibir o email do dono na listagem de forma amigável
    def owner_email_display(self, obj):
        return obj.owner.email
    # Nome da coluna
    owner_email_display.short_description = 'Owner Email'  # type: ignore

# Registra o CustomUser usando a classe de admin customizada


admin.site.register(CustomUser, CustomUserAdmin)
