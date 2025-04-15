from rest_framework import serializers
# Importar validação de senha do Django (opcional, mas recomendado)
from django.contrib.auth.password_validation import (
    validate_password as django_validate_password
)
from django.core.exceptions import ValidationError as DjangoValidationError

from .models import CustomUser, Item


# Esse serializer é usado para expor os dados do usuário na API
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        # Campos expostos na API
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'profile_image', 'email_confirmed'
        ]
        # Só leitura
        read_only_fields = ['id', 'email_confirmed']


# Serializer específico para o processo de registro
class RegisterSerializer(serializers.ModelSerializer):
    # Adiciona campos extras que não estão no modelo diretamente, mas são
    # necessários para o registro
    password = serializers.CharField(
        write_only=True, required=True, style={'input_type': 'password'}
    )
    password2 = serializers.CharField(
        write_only=True, required=True, label='Confirm password',
        style={'input_type': 'password'}
    )

    class Meta:
        model = CustomUser
        # Campos necessários para criar um novo usuário via API
        fields = [
            'username', 'email', 'first_name', 'last_name', 'password',
            'password2', 'profile_image'
        ]
        extra_kwargs = {
            # Garante que nome e sobrenome sejam enviados no registro
            'first_name': {'required': True},
            'last_name': {'required': True},
            # Imagem de perfil é opcional no registro
            'profile_image': {'required': False}
        }

    # Validação extra: verificar se as senhas coincidem
    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        # (Opcional, mas recomendado) Validar se email/username já existem
        # aqui para dar feedback antes
        if CustomUser.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError(
                {"email": "A user with that email already exists."}
            )
        if CustomUser.objects.filter(username=attrs['username']).exists():
            raise serializers.ValidationError(
                {"username": "A user with that username already exists."}
            )
        return attrs

    # Método chamado quando o serializer precisa criar um novo objeto (usuário)
    def create(self, validated_data):
        # Remove o campo 'password2' que não vai para o banco
        validated_data.pop('password2')
        # Pega a senha para tratar separadamente (hashing)
        password = validated_data.pop('password')
        # Cria a instância do usuário com os dados validados restantes
        user = CustomUser(**validated_data)
        # Define a senha usando o método que faz o hashing (encriptação)
        user.set_password(password)
        # Garante que o email não está confirmado ao se registrar
        user.email_confirmed = False
        # Salva o usuário no banco de dados
        user.save()
        return user


# Serializer para os Itens
class ItemSerializer(serializers.ModelSerializer):
    # Campo extra para mostrar o email do dono (somente leitura)
    # Facilita para quem consome a API não ter que fazer outra requisição
    # pelo ID do dono
    owner_email = serializers.ReadOnlyField(source='owner.email')

    class Meta:
        model = Item
        # campos do Item que serão expostos na API
        fields = [
            'id', 'title', 'description', 'is_public', 'created_at', 'owner',
            'owner_email'
        ]
        # campos que são definidos pelo sistema ou não devem ser enviados
        # diretamente pelo usuário
        read_only_fields = ['id', 'created_at', 'owner', 'owner_email']
        # opcional
        extra_kwargs = {
            'description': {'required': False}
        }


# Novo Serializer para Alteração de Senha
class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer para o processo de alteração de senha.

    Requer a senha antiga e a nova senha (com confirmação).
    """
    old_password = serializers.CharField(
        required=True,
        write_only=True,  # Não queremos ler/expor a senha antiga
        style={'input_type': 'password'}
    )
    new_password1 = serializers.CharField(
        required=True,
        write_only=True,  # Não expor a nova senha
        style={'input_type': 'password'},
        help_text='Sua nova senha.'  # Ajuda para a documentação da API
    )
    new_password2 = serializers.CharField(
        required=True,
        write_only=True,  # Não expor a confirmação
        style={'input_type': 'password'},
        help_text='Confirme sua nova senha.'  # Ajuda para a documentação da API
    )

    def validate(self, data):

        # 1. Verifica se a nova senha e a confirmação são iguais
        if data['new_password1'] != data['new_password2']:
            # O erro é associado ao campo 'new_password2' para clareza
            raise serializers.ValidationError(
                {"new_password2": "As novas senhas não coincidem."}
            )

        # 2. (Opcional, mas recomendado) Valida a força da nova senha usando
        # validadores do Django
        # Pega o usuário a partir do contexto passado pela View
        user = self.context['request'].user
        try:
            django_validate_password(password=data['new_password1'], user=user)
        except DjangoValidationError as e:
            # Converte o erro de validação do Django para um erro do DRF
            raise serializers.ValidationError(
                {"new_password1": list(e.messages)}
            )

        # 3. (Opcional) Verifica se a nova senha é diferente da antiga
        # if data['new_password1'] == data['old_password']:
        #     raise serializers.ValidationError(
        #         {"new_password1": "A nova senha deve ser diferente da senha antiga."}
        #     )

        return data


# --- Novo Serializer para Validar Token de Confirmação ---
class ValidateConfirmationSerializer(serializers.Serializer):
    """
    Serializer simples para receber o token UUID enviado pelo usuário
    para validar o e-mail.
    """
    token = serializers.UUIDField(
        required=True,
        help_text="O token UUID recebido para confirmação."
    )
