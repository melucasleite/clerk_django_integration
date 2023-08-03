from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from clerk_django_integration import views

router = routers.DefaultRouter()
router.register(r"users", views.UserViewSet)

urlpatterns = [
    path("api/", include(router.urls)),
    path("admin/", admin.site.urls),
]
