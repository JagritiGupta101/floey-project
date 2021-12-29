from django.urls import path,include
from django.views.decorators.csrf import csrf_exempt
from rest_framework.routers import DefaultRouter
from .views import *

r = DefaultRouter()

r.register('',User_Class)
r.register('roles/permissions',RolePermsAPI,basename='roleperms')

urlpatterns = [
    path('',include(r.urls)),
    path('select/gym/',Selected_gym.as_view()),
    path('subscribed/userslist/',SubscribedUserList.as_view()),
    path('userhistory/<str:pk>/',UserHistoryDetail.as_view()),  

    path('bookclass/list/',BookClass.as_view()),
    path('subscription/user/',subscription.as_view()),

    path('class/Bookings/',Bookings.as_view()),
    path('upcomingclass/list/',UpcomingBookClass.as_view()),

    path('admin/create/',AdminCreateList.as_view()),
    path('admin/action/<str:pk>/',AdminAction.as_view()),
    path('admin/login/',csrf_exempt(AdminLoginView.as_view())),
    path('export/csv/',user_data_async),

    # path('rest-auth/google/', GoogleLogin.as_view(), name='google_login')

     path('bookcourse/list/',BookCourse.as_view()),
     path('course/Bookings/',CourseBookings.as_view()),
     path('upcomingcourse/list/',UpcomingBookCourse.as_view()),
     path('home/user_profile/',UserProfile.as_view()),
     path('home/schedule/',GetSchedules.as_view()),

]