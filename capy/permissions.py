# capy/permissions.py

from rest_framework import permissions


class IsEmailConfirmed(permissions.BasePermission):
    """
    Permissão customizada que permite acesso apenas a usuários autenticados
    E que tenham confirmado seu endereço de e-mail.
    """
    # Mensagem que será retornada se a permissão for negada
    message = 'Seu endereço de e-mail precisa ser confirmado.'

    def has_permission(self, request, view):
        """
        Verifica se o usuário da requisição está autenticado E
        se o campo 'email_confirmed' dele é True.
        """

        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.email_confirmed  # A verificação chave!
        )
