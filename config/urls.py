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

# --- drf-yasg Configuration ---
schema_view = get_schema_view(
   openapi.Info(
      title="Capyba Challenge API",  # Your API Title
      default_version='v1',        # API Version
      description="API documentation for the Capyba technical challenge.",
      contact=openapi.Contact(email="lucasajorge@gmail.com"),
   ),
   public=True,  # Makes the schema public (accessible without login)
   permission_classes=(permissions.AllowAny,),
)
# ---------------------------------

urlpatterns = [
    # Redirects the root URL '/' to the documentation '/swagger/'
    path('', RedirectView.as_view(url='/swagger/',
         permanent=False), name='index'),
    path('admin/', admin.site.urls),
    # Include the capy app URLs under /api/
    path('api/', include('capy.urls')),
    # --- drf-yasg Documentation URLs ---
    # Endpoint for the raw JSON schema
    re_path(r'^swagger(?P<format>\.json|\.yaml)$',
            schema_view.without_ui(cache_timeout=0), name='schema-json'),
    # Endpoint for the interactive Swagger UI interface
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0),
         name='schema-swagger-ui'),
    # Endpoint for the Redoc interface (alternative/complementary)
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0),
         name='schema-redoc'),
    # --------------------------------------
]
