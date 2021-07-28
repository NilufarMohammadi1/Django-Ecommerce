from django.urls import path
from . import views


urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/',views.login_user,name='login'),
    path('logout/',views.logout,name='logout'),
    path('activate/<uidb64>/<token>/',views.activate,name="activate"),
    path('dashboard/',views.dashboard,name="dashboard"),
    path('',views.dashboard,name="dashboard"),
    path('forgotPassword/', views.forgotPassword, name='forgotPassword'),
    path('resetpassword_validate/<uidb64>/<token>/', views.resetpassword_validate, name='resetpassword_validate'),
   
    path('resetPassword/', views.resetPassword, name='resetPassword'),

]