"""GYM URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
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
from django.shortcuts import render
from django.urls import path,include
from django.conf.urls.static import static
from django.conf import settings

from rest_framework import permissions
# from drf_yasg.views import get_schema_view
# from drf_yasg import openapi


# schema_view = get_schema_view(
#     openapi.Info(
#         title="GYM DASHBOARD API",
#         default_version='v1',
#         description="Test description",
#         terms_of_service="https://www.ourapp.com/policies/terms/",
#         contact=openapi.Contact(email="contact@expenses.local"),
#         license=openapi.License(name="Test License"),
#     ),
#     public=True,
#     permission_classes=(permissions.AllowAny,),
# )


from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

# def geeks_view(request):
#     return render(request, "home.html")

urlpatterns = [
    # path('',geeks_view),
    path('admin/', admin.site.urls),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api-auth/', include('rest_framework.urls')),
    # path('admin/', include(('vali.urls','vali'), namespace='dashboard')),
    path('user/', include('user.urls')),
    path('gymprofile/', include('gymprofile.urls')),
    path('payments/',include('payments.urls')),
    path('social/',include('social_auth.urls')),


    # path('', schema_view.with_ui('swagger',
    #                              cache_timeout=0), name='schema-swagger-ui'),

    # path('api/api.json/', schema_view.without_ui(cache_timeout=0),
    #      name='schema-swagger-ui'),
    # path('redoc/', schema_view.with_ui('redoc',
    #                                    cache_timeout=0), name='schema-redoc'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


if settings.DEBUG: # new
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

