"""config URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.generic import RedirectView
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# --- Configuração do drf-yasg ---
schema_view = get_schema_view(
   openapi.Info(
      title="Capyba Challenge API",  # Título da sua API
      default_version='v1',        # Versão da API
      description="Documentação da API para o desafio técnico da Capyba.",
      contact=openapi.Contact(email="lucasajorge@gmail.com"),
   ),
   public=True,  # Torna o schema público (acessível sem login)
   permission_classes=(permissions.AllowAny,),
)
# ---------------------------------

urlpatterns = [
    # Redireciona a URL raiz '/' para a documentação '/swagger/'
    path('', RedirectView.as_view(url='/swagger/',
         permanent=False), name='index'),
    path('admin/', admin.site.urls),
    # Include the capy app URLs under /api/
    path('api/', include('capy.urls')),
    # --- URLs da Documentação drf-yasg ---
    # Endpoint para o schema JSON bruto
    re_path(r'^swagger(?P<format>\.json|\.yaml)$',
            schema_view.without_ui(cache_timeout=0), name='schema-json'),
    # Endpoint para a interface Swagger UI interativa
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0),
         name='schema-swagger-ui'),
    # Endpoint para a interface Redoc (alternativa/complementar)
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0),
         name='schema-redoc'),
    # --------------------------------------
]
