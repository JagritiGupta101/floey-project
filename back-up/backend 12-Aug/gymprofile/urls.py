from django.urls import path,include
from .views import *
from rest_framework.routers import DefaultRouter

r = DefaultRouter()

r.register('',GymtimeApi)


urlpatterns = [
    path('gymtime/',include(r.urls)),
    path('',GymProfileAPIView.as_view(),name = 'gymprofilelist'),
    path('gymroles/',RolesListView.as_view()),
    path('gymroles/<str:uuid>',RoleDetail.as_view()),
    path('searchgym/',SearchGymView.as_view(),name = 'serachgym'),
    path('gym/<str:uuid>/',GymDetailView.as_view(),name = 'gymprofiledetail'),
    path('manager/',GymMembersList.as_view(),name = 'gymusers'),
    path('packages/',PackageslistAPIView.as_view(),name = 'packages'),
    path('packages/<str:uuid>/',PackagesdetailView.as_view(),name = 'packagesdetail'),
    path('membership/',MembershipAPIView.as_view(),name = 'membership'),
    path('membership/<str:uuid>/',MembershipdetailView.as_view(),name = 'membershipdetail'),
    path('facilities/',FacilitiesAPIView.as_view(),name = 'facilities'),
    path('instructor/',InstructorAPIView.as_view(),name = 'instructor'),
    path('instructor/<str:uuid>/',InstructorDetailView.as_view(),name = 'instructordetail'),

    path('course/',CourseAPIView.as_view(),name = 'course'),
    path('course/<str:pk>/',CoursedetailView.as_view(),name = 'coursedetail'),

    path('classes/',ClassAPIView.as_view(),name = 'classes'),
    path('classes/<str:pk>/',ClassdetailView.as_view(),name = 'classesdetail'),

    path('online/',OnlineListView.as_view(),name = 'online'),
    path('online/<str:uuid>/',OnlinedetailView.as_view(),name = 'onlinedetail'),
    path('weekdays/',WeekdaysAPIView.as_view(),name = 'weekdays'),
    path('location/',LocationAPIView.as_view(),name = 'location'),
    path('location/<str:uuid>/',LocationDetail.as_view(),name = 'locationdetail'),
    path('age_group/',AgeAPIView.as_view(),name = 'age_group'),
    path('dateslots/',Dates.as_view(),name = 'dateslots'),
    path('holidays/',HolidayView.as_view(),name = 'holiday'),
    path('holidays/<str:uuid>/',HolidaydetailView.as_view(),name = 'holidaydetail'),
    path('policy/',PolicyView.as_view(),name = 'policy'),
    path('policy/<str:uuid>/',PolicydetailView.as_view(),name = 'policydetail'),
    
    path('zymclasses/',Zymclasses.as_view(),name = 'zymclasses'),
    
    path('get_class/<str:id>/',ClassDetailById.as_view(),name = 'get_class'),
    path('get_course/<str:id>/',CourseDetailById.as_view(),name = 'get_course'),

    path('recommended/',RecommendedSection.as_view(),name = 'recommended'),
    path('ammenities/',AmmenitiesView.as_view(),name = 'ammenities'),
    path('ammenities/<str:uuid>/',AmmenitiesDetailView.as_view(),name = 'ammenitiesdetail'),
    path('classdate/',ClassByDate.as_view(),name = 'classdate'),
    path('gymlist/',GymList.as_view(),name = 'gymlist'),
    path('classList/',ClassesList.as_view(),name = 'classList'),
    path('class/date/',ClassByDate.as_view()),
    path('expense/',ExpenseslistApi.as_view()),
    path('expense/<str:uuid>/',ExpensesDetailView.as_view()),
    path('reports/',Reports.as_view()),
    path('instructorclass/',Instructorclass.as_view()),
    path('dash/',Dashboard.as_view()),
    path('reports/csv/',Reports_CSV.as_view()),

    path('course_timeline',CourseTimeline.as_view())
    
]

