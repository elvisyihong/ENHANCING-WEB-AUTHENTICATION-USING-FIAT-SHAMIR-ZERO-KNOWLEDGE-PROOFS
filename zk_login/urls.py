from django.urls import path
from .views import *

urlpatterns = [
    path('zk-challenge/', zk_challenge, name='zk_get_challenge'),
    path('login/', login_view, name='login'),
    path('register/', register, name='register'),
    path('home/', home, name='home'),
    path('logout/', logout, name='logout'),
]
