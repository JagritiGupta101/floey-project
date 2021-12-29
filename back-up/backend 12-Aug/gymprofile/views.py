# from django.shortcuts import render
from rest_framework import response
from .models import *
from .serializers import *
from rest_framework import viewsets,status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from datetime import datetime,date,timedelta
from rest_framework import generics
from rest_framework import filters
from django.db.models import Q
from user.models import *
from django.views.decorators.csrf import csrf_exempt
from user.serializers import *
from dateutil.relativedelta import relativedelta
import calendar
# import datetime

# Create your views here.
months = {'Jan':1,'Feb':2,'Mar':3,'April':4,'May':5,'June':6,'July':7,
        'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
class GymtimeApi(viewsets.ModelViewSet):
    queryset = GymTime.objects.all()
    serializer_class = GymTimeSerializer

class GymProfileAPIView(APIView):
    def get(self,request):
        data = request.GET
        vlaue = GymProfile.objects.all()
        context=[]
        for i in vlaue:
            post = GymProfileSerializer(i).data
            age = i.age_criteria.age
            time = i.gym_timings.time_text
            post.update({
                'age_criteria':age,
                'gym_timings':time
            })
            context.append(post)
        return Response(context)
    
    def post(self,request):
            data = request.data
            res_serializer = GymProfileSerializer(data = data)
            if res_serializer.is_valid():
                res_serializer.save()
                return Response(res_serializer.data)
            return Response(res_serializer.errors)

class RolesListView(APIView):
    def get(self,request):
        data = request.GET
        query = Role.objects.filter(gym = data.get('gym'))
        ser  = RoleSerializer(query,many = True)
        return Response(ser.data)
    def post(self,request):
        data = request.data
        ser = RoleSerializer(data = data)
        if ser.is_valid():
            ser.save()
            return Response(ser.data)
        return Response(ser.errors)

class RoleDetail(APIView):
    def get(self,request,uuid):
        package = Role.objects.get(uuid=uuid)
        post = RoleSerializer(package).data
        gym = package.gym.gym_name
        post.update({
            'gym':gym
        })
        return Response(post)
    
    def patch(self,request,uuid):
        data = request.data
        if not Role.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        package = Role.objects.get(uuid=uuid)
        ser = RoleSerializer(package,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)

    def delete(self, request, uuid):
        snippet = Role.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})

class GymMembersList(APIView):
    def get(self,request):
        data = request.GET
        query = GymManager.objects.get(gym = data.get('gym'))
        ser = GymManagerSerializer(query).data
        employees = query.employee.all()
        context=[]
        for i in employees:
            employee = i.first_name + ' ' + i.last_name
            email = i.email
            role = i.user_role.user_roles
            uuid = i.uuid
            context.append({
                'name':employee,
                'email':email,
                'role':role,
                'uuid':uuid
            })
        ser.update({
            'employee':context
        })
        return Response(ser)
    
    def post(self,request):
        data = request.data
        ser = GymMemberSerializer(data = data)
        if ser.is_valid():
            user = ser.save()
            obj = GymManager.objects.get(gym = data.get('gym'))
            obj.employee.add(user)
           
            admin = AdminPermissions.objects.create(userinfo = user,perm_role = RoleWisePermissions.objects.get(for_role=data['user_role'],gym = data.get('gym')))

            if  Role.objects.get(uuid = data['user_role']).user_roles == 'Instructor':
                ins = Instructor()
                ins.instructor_info = User.objects.get(first_name = data.get('first_name'))
                ins.gym = GymProfile.objects.get(uuid = data.get('gym'))          
                ins.save()

            return Response(ser.data)
        return Response(ser.errors)

class SearchGymView(APIView):
    def post(self,request):
        data = request.data
        gym = GymProfile.objects.get(uuid = data.get('id'))
        if gym:
            ser = GymProfileSerializer(gym).data
            return Response(ser)
        else:
            return Response('Gym not Found')

class GymDetailView(APIView):
    def get(self,request,uuid):
        value = GymProfile.objects.get(uuid=uuid)
        post = GymProfileSerializer(value).data
        age = value.age_criteria.age
        time = value.gym_timings.time_text
        location = value.city.all()
        loactionlist=[]
        for i in location:
            location = i.gym_location
            loactionlist.append(location)
        days= value.opening_days.all()
        context=[]
        for i in days:
            day = i.day
            context.append(day)
        post.update({
            'age_criteria':age,
            'gym_timings':time,
            'opening_days':context,
            'city':loactionlist
        })
        return Response(post)
    
    def patch(self,request,uuid):
        data = request.data
        if not GymProfile.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        obj = GymProfile.objects.get(uuid=uuid)
        ser = GymProfileSerializer(obj,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)

    # def delete(self, request, uuid):
    #     import pdb; pdb.set_trace()
    #     obj = GymProfile.objects.get(uuid=uuid)
    #     obj.delete()
    #     return Response({"message":"Delete Successfully"})


class PackageslistAPIView(APIView):
    
    def get(self,request):
        # import pdb;pdb.set_trace()
        data = request.GET
        vlaue = Packages.objects.filter(gym = data.get("gym_id"))
        context =[]
        for i in vlaue:
            list_classes = []
            post = PackagesSerializer(i).data
            classes = i.class_passes
            gym = i.gym.gym_name
            post.update({
                    'class_count':classes,
                    'gym':gym
                        })
            context.append(post)
        return Response(context)
    
    def post(self,request):
        data = request.data            
        res_serializer = PackagesSerializer(data = data)
        if res_serializer.is_valid():
            res_serializer.save()
            return Response(res_serializer.data)
        return Response(res_serializer.errors)
    
class PackagesdetailView(APIView):

    def get(self,request,uuid):
        package = Packages.objects.get(uuid=uuid)
        post = PackagesSerializer(package).data
        gym = package.gym.gym_name
        post.update({
            'gym':gym
        })
        return Response(post)
    
    def patch(self,request,uuid):
        data = request.data
        if not Packages.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        package = Packages.objects.get(uuid=uuid)
        ser = PackagesSerializer(package,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)

    def delete(self, request, uuid):
        
        snippet = Packages.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})

class MembershipAPIView(APIView):
    
    def get(self,request):
        
        data = request.GET     
        vlaue = Membership.objects.filter(gym = data.get('gym_id'))
        post = MembershipSerializer(vlaue, many=True)
        return Response(post.data)
        # vlaue = Membership.objects.filter(gym = data.get("gym_id"))
        # context =[]
        # for i in vlaue:
        #     list_classes = []
        #     post = MembershipSerializer(i).data
        #     classes = i.membership_duration
        #     gym = i.gym.gym_name
        #     post.update({
        #             'class_count':classes,
        #             'gym':gym
        #                 })
        #     context.append(post)
        # return Response(context)
    
    def post(self,request):
            data = request.data            
            res_serializer = MembershipSerializer(data = data)
            if res_serializer.is_valid():
                res_serializer.save()
                return Response(res_serializer.data)
            return Response(res_serializer.errors)
        # return Response("Not Authorized")
    
class MembershipdetailView(APIView):

    def get(self,request,uuid):
        
        package = Membership.objects.get(uuid=uuid)
        post = MembershipSerializer(package).data
        age = package.membership_age_group.age
        location = package.select_location.gym_location
        post.update({
            "membership_age_group":age,
            "select_location":location
        })
        return Response(post)
    
    def patch(self,request,uuid):
        data = request.data
        
        if not Membership.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        membership = Membership.objects.get(uuid=uuid)
        ser = MembershipSerializer(membership,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)
    
    def delete(self, request, uuid):
        
        snippet = Membership.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})

class FacilitiesAPIView(APIView):
    
    def get(self,request):          
        vlaue = Facilities.objects.all()
        post = FacilitiesSerializer(vlaue, many=True)
        return Response(post.data)
    
    def post(self,request):
        if request.user.user_role == "Gym Owner":
            data = request.data
            res_serializer = FacilitiesSerializer(data = data)
            if res_serializer.is_valid():
                res_serializer.save()
                return Response(res_serializer.data)
            return Response(res_serializer.errors)
        return Response("Not Authorized")

class InstructorAPIView(APIView):
    
    def get(self,request):
        data = request.GET
        
        vlaue = Instructor.objects.filter(gym = data.get('gym_id'))
        context=[]
        for val in vlaue:
            post = InstructorSerializer(val).data
            ins_info  = val.instructor_info.first_name
            created = val.created_at.strftime('%D')
            post.update({
                'instructor_info':ins_info,
                'created_at':created
            })
            context.append(post)
        return Response(context)
    
    def post(self,request):
        data = request.data
        
        res_serializer = InstructorSerializer(data = data)
        if res_serializer.is_valid():
            res_serializer.save()
            return Response(res_serializer.data)
        return Response(res_serializer.errors)

class InstructorDetailView(APIView):
    def get(self,request,uuid):
        
        value = Instructor.objects.get(uuid = uuid)
        ins_info  = value.instructor_info.first_name
        ser = InstructorSerializer(value).data
        # ser.update({'instructor_info':ins_info})
        return Response(ser)
    
    def patch(self,request,uuid):
        data = request.data
        
        if not Instructor.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        value = Instructor.objects.get(uuid=uuid)
        ser = InstructorSerializer(value,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)
            
    def delete(self, request, uuid):
        
        snippet = Instructor.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})

class CourseAPIView(APIView):
    
    def get(self,request):
        # import pdb; pdb.set_trace()
        
        
        data = request.GET
        month=months[data.get('month')]
        year = int(data.get('year'))
        # range = calendar.monthrange(year,month)

        vlaue = Course.objects.filter(gym = data.get("gym_id"))
        context = []
        for i in vlaue:
            if i.course_start_date.year==year and i.course_start_date.month==month:#and i.course_start_date>date.today():
                context.append(i.uuid)
                
        return Response(context)

    def post(self,request):
        # if request.user.role == "Gym Owner":
            
            data = request.data
            res_serializer = CourseSerializer(data = data)
            if res_serializer.is_valid():
                res_serializer.save()
                return Response(res_serializer.data)
            return Response(res_serializer.errors)
        # return Response('Not Authorized')
  
class CoursedetailView(APIView):

    def get(self,request,uuid):
        
        package = Course.objects.get(uuid=uuid)
        post = CourseSerializer(package).data
        context=[]
        if package.course_scheduled_on:
            schedule = package.course_scheduled_on.all()
            for i in schedule:
                day = i.day
                context.append(day)
            post.update({"course_scheduled_on":', '.join(context)})
        if package.course_age_group:
            age = package.course_age_group.age
            post.update({'course_age_group':age})
        if package.select_location:
            location= package.select_location.gym_location
            post.update({'select_location':location})
        if package.instructor_info:
            instructor_name = package.instructor_info.instructor_info.first_name
            post.update({'instructor_info':instructor_name})
    
        return Response(post)
    
    def patch(self,request,uuid):
        data = request.data
        
        if not Course.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        course = Course.objects.get(uuid=uuid)
        ser = CourseSerializer(course,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)
    
    def delete(self, request, uuid):
        
        snippet = Course.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})

class ClassAPIView(APIView):
    
    def get(self,request,pk):
        # import pdb; pdb.set_trace()
        
        data = request.GET
        vlaue = Classes.objects.filter(gym = data.get('gym_id'))        
        context = []
        for v in vlaue:
            post = ClassSerializer(v).data
            gym = v.gym.gym_name
            location = v.select_location.gym_location
            st_t = v.start_time.strftime('%H:%M')
            end_t = v.end_time.strftime('%H:%M')
            duration= int(v.end_time.strftime('%H')) - int(v.start_time.strftime('%H'))
            m_duration = int(v.end_time.strftime('%M')) - int(v.start_time.strftime('%M'))
            if v.instructor_info:
                instructor_name = v.instructor_info.instructor_info.first_name
                post.update({'instructor_info':instructor_name})
            today = date.today()
            end_date = today + timedelta(30)
            get_list=[]
            for dt in range(30):
                if v.class_scheduled_on.filter(int_day = dt).exists():
                    get_class = v.class_scheduled_on.filter(int_day = dt)
                    x = WeekdaysSerializer(get_class,many =True)
                    get_list.append(x.data)
            # print(get_list)
            post.update({
                        'duration':str(duration),
                        'min_duration':str(m_duration),
                        'location':location,
                        'class_scheduled_on':get_list,
                        'start_time':st_t,
                        'end_time':end_t,
                        'start':today,
                        'end':end_date,
                        'gym':gym
                        
                    })
            context.append(post)
        return Response(context)
    
    def post(self,request):
        
        data = request.data
        res_serializer = ClassSerializer(data = data)
        if res_serializer.is_valid():
            res_serializer.save()
            return Response(res_serializer.data)
        return Response(res_serializer.errors)

class ClassdetailView(APIView):

    def get(self,request,pk):
        # import pdb;pdb.set_trace()
        package = Classes.objects.get(uuid=pk)
        post = ClassSerializer(package).data
        if package.instructor_info:
                instructor_name = package.instructor_info.instructor_info.first_name
                post.update({'instructor_info':instructor_name})
        if package.classes_age_group:
            age = package.classes_age_group.age
            post.update({'classes_age_group':age})
        if package.select_location:
            location = package.select_location.gym_location
            post.update({'select_location':location})
        if package.class_scheduled_on:
            shedule = package.class_scheduled_on.all()
            context = []
            for i in shedule:
                day = i.day
                context.append(day)
            post.update({'class_scheduled_on':', '.join(context)})
       
        return Response(post)

    def patch(self,request,uuid):
        data = request.data
        
        if not Classes.objects.filter(uuid=data.get('uuid')).exists():
            return Response('Unauthorized')
        classses = Classes.objects.get(uuid=data.get('uuid'))
        ser = ClassSerializer(classses,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)
    
    def delete(self, request, pk):
        # import pdb;pdb.set_trace()
        snippet = Classes.objects.get(uuid = pk)
        snippet.delete()
        return Response({'data':"Deleted"})

class OnlineListView(APIView):

    def get(self,request):
        data = request.GET
        query = Online.objects.filter(gym = data.get('gym'))
        context = []
        for val in query:
            ser = OnlineSerializer(val).data
            if val.online_instructor:
                instructor_name = val.online_instructor.instructor_info.first_name
                ser.update({'online_instructor':instructor_name})
            context.append(ser)
        return Response(context)

    def post(self,request):
        
        data = request.data
        res_serializer = OnlineSerializer(data = data)
        if res_serializer.is_valid():
            res_serializer.save()
            return Response(res_serializer.data)
        return Response(res_serializer.errors)

class OnlinedetailView(APIView):

    def get(self,request,uuid):
        
        package = Online.objects.get(uuid=uuid)
        post = OnlineSerializer(package).data
        if package.online_instructor:
            instructor = package.online_instructor.instructor_info.first_name
            post.update({"online_instructor":instructor})
        return Response(post)

    def patch(self,request,uuid):
        data = request.data
        
        if not Online.objects.filter(uuid=data.get('uuid')).exists():
            return Response('Unauthorized')
        classses = Online.objects.get(uuid=data.get('uuid'))
        ser = OnlineSerializer(classses,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)
    
    def delete(self, request, uuid):
        
        snippet = Online.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})

class WeekdaysAPIView(APIView):
    def get(self,request):
            vlaue = Weekdays.objects.all()
            post = WeekdaysSerializer(vlaue, many = True)
            return Response(post.data)

class LocationAPIView(APIView):
    def get(self,request):
        data=  request.GET
        vlaue = GymProfile.objects.filter(uuid = data.get('gym'))[0].city.all()
        post = LocationSerializer(vlaue, many = True)
        return Response(post.data)
        
    def post(self,request):
        
        data = request.data
        ser = LocationSerializer(data=data)
        if ser.is_valid():
            ser.save()
            return Response(ser.data)
        else:
            return Response(ser.errors)

class LocationDetail(APIView):
    def get(self,request,uuid):
        
        value = Location.objects.get(uuid = uuid)
        ser = LocationSerializer(value).data
        return Response(ser)
    
    def patch(self,request,uuid):
        data = request.data
        
        if not Location.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        value = Location.objects.get(uuid=uuid)
        ser = LocationSerializer(value,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)
            
    def delete(self, request, uuid):
        
        snippet = Location.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})

class AgeAPIView(APIView):
    def get(self,request):
            vlaue = Age_Group.objects.all()
            post = AgeSerializer(vlaue, many = True)
            return Response(post.data)

class Dates(APIView):   
    
    def daterange(self,date1, date2):
        for n in range(int((date2 - date1).days) + 1):
            yield date1 + timedelta(n)

    def get(self,request):
        # import pdb;pdb.set_trace()
        date_slots = []
        d_slots=["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]
        start_dt = date.today()
        end_dt = start_dt + timedelta(7)
        city = Location.objects.get(gym_location=request.query_params['city'])
        try:
            instance = Classes.objects.filter(select_location=city)
            for dt in self.daterange(start_dt, end_dt):
                if not Holiday.objects.filter(start_date__lte=dt,end_date__gte=dt).exists():
                    d = dt.strftime('%d %b %Y')
                    day = dt.strftime('%A')
                    if start_dt==dt:
                        day = 'Today'
                    date_slots.append({"date_init":dt.strftime('%d'),"date": d,"day":day})
                else:
                    continue
            return Response(date_slots)
        except Exception as e:
            return Response(str(e))

class Zymclasses(APIView):
    def get(self,request):
        
        data = request.GET
        date = request.query_params['date']
        date_time_obj = datetime.strptime(date, '%d %b %Y')
        day_string = date_time_obj.strftime('%a')
        classes  = Classes.objects.filter(class_scheduled_on__day__icontains=day_string,gym = data.get('gym_id'))

        context = []
        for v in classes:
            if v.is_active==True:
                context.append(v.uuid)

        return Response(context)


class ClassDetailById(APIView):
    def get(self,request,id):
        # import pdb; pdb.set_trace()
        data = request.GET
        ser={}
        date = request.query_params['date']
        date_time_obj = datetime.strptime(date, '%d %b %Y')
        day_string = date_time_obj.strftime('%a')
        class_obj  = Classes.objects.get(uuid=id)

        
        if UserClass.objects.filter(select_classes = class_obj,booked_date = date_time_obj).exists():
            get = UserClass.objects.filter(select_classes = class_obj,booked_date = date_time_obj)[0]
            seat_available = get.seat_available
        else:
            seat_available = class_obj.no_of_participants

        # if class_obj.start_time > datetime.today().time() or datetime.today() < date_time_obj:
        ser = ClassSerializer(class_obj).data
        gym = class_obj.gym.gym_name
        st_t = class_obj.start_time.strftime('%H:%M')
        location = class_obj.select_location.gym_location
        end_t = class_obj.end_time.strftime('%H:%M')
        duration= int(class_obj.end_time.strftime('%H')) - int(class_obj.start_time.strftime('%H'))
        m_duration = int(class_obj.end_time.strftime('%M')) - int(class_obj.start_time.strftime('%M'))
        age = class_obj.classes_age_group.age

        ser.update({
                    'class_date':data.get('date'),
                    'duration':str(duration),
                    'min_duration':str(m_duration),
                    'location':location,
                    'start_time':st_t,
                    'end_time':end_t,
                    'gym':gym,
                    'classes_age_group':age,
                    'no_of_participants':seat_available
                })
    

        return Response(ser)

class CourseDetailById(APIView):
    def get(self,request,id):
        
        i = Course.objects.get(uuid=id)
        
        post = CourseSerializer(i).data
        print(post)
        gym = i.gym.gym_name
        location = i.select_location.gym_location #= i.select_location.gym_location
        course_start_date =  i.course_start_date.strftime("%d %B %Y")
        course_end_date =  i.course_end_date.strftime("%d %B %Y")
        start_month = i.course_start_date.strftime("%B")

        if i.instructor_info:
            instructor_name = i.instructor_info.instructor_info.first_name
            post.update({'instructor_info':instructor_name})
        
        post.update({
                    'start_month':start_month[:3],
                    'course_start_date':course_start_date,
                    'course_end_date':course_end_date,
                    'gym':gym,
                    'course_age_group':i.course_age_group.age,
                    'select_location':location,
                    'course_scheduled_on':i.course_scheduled_on.all().values_list('day',flat=True),
                })
        return Response(post)


class CourseTimeline(APIView):
    def get(self,request):
        res=[]
        for i in range(0,13):
            # print(i)
            td =datetime.today()+relativedelta(months=i)
            # print(td)
            month=None
            for i in months:
                month = i if months[i]==td.month else None
                if month:
                    break
            res.append({'year':td.year,'month':month})
        return Response(res)

        
class HolidayView(APIView):

    def get(self,request):
        
        data = request.GET
        if Holiday.objects.filter(gym = data.get("gym_id")).exists():
            val = Holiday.objects.filter(gym = data.get("gym_id"))
            context = []
            for item in val:
                ser = HolidaySerializer(item).data
                context.append(ser)
            return Response(context)
        return Response(data)

    def post(self,request):
            
            data = request.data
            res_serializer = HolidaySerializer(data = data)
            if res_serializer.is_valid():
                res_serializer.save()
                return Response(res_serializer.data)
            return Response(res_serializer.errors)

class HolidaydetailView(APIView):
    
    def get(self,request,uuid):
        value = Holiday.objects.get(uuid = uuid)
        ser = HolidaySerializer(value)
        return Response(ser.data)
    
    def patch(self,request,uuid):
        data = request.data
        
        if not Holiday.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        value = Holiday.objects.get(uuid=uuid)
        ser = HolidaySerializer(value,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)
    
    def delete(self, request, uuid):
        
        snippet = Holiday.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})

class PolicyView(APIView):
    def get(self,request):
        data = request.GET
        if CancellationPolicy.objects.filter(gym = data.get('gym_id')).exists():
            val = CancellationPolicy.objects.filter(gym = data.get("gym_id"))
            context = []
            for item in val:
                ser = CancellationPolicySerializer(item).data
                context.append(ser)
            return Response(context)
        return Response(data)
    
    def post(self,request):
            
            data = request.data
            res_serializer = CancellationPolicySerializer(data = data)
            if res_serializer.is_valid():
                res_serializer.save()
                return Response(res_serializer.data)
            return Response(res_serializer.errors)

class PolicydetailView(APIView):
    
    def get(self,request,uuid):
        value = CancellationPolicy.objects.get(uuid = uuid)
        ser = CancellationPolicySerializer(value)
        return Response(ser.data)
    
    def patch(self,request,uuid):
        data = request.data
        
        if not CancellationPolicy.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        value = CancellationPolicy.objects.get(uuid=uuid)
        ser = CancellationPolicySerializer(value,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)
            
    def delete(self, request, uuid):
        
        snippet = CancellationPolicy.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})
          
class RecommendedSection(APIView):

    def get(self,request):
        data = request.GET
        if GymProfile.objects.filter(uuid = data.get("gym_id")).exists():
            date = request.query_params['date']
            date_time_obj = datetime.strptime(date, '%Y-%m-%d')
            day_string = date_time_obj.strftime('%a')
            classes  = Classes.objects.filter(class_scheduled_on__day=day_string)
            return Response(ClassSerializer(classes, many=True).data)
        return Response(data)

class AmmenitiesView(APIView):
    
    def get (self,request):
        data = request.GET
        
        if Ammenities.objects.filter(gym = data.get("gym_id")).exists():
            val = Ammenities.objects.filter(gym = data.get("gym_id"))
            context = []
            for item in val:
                ser = AmmenitiesSerializer(item).data
                context.append(ser)
            return Response(context)
        return Response(data)
    
    def post(self,request):
        
        data = request.data
        res_serializer = AmmenitiesSerializer(data = data)
        if res_serializer.is_valid():
            res_serializer.save()
            return Response(res_serializer.data)
        return Response(res_serializer.errors)

class AmmenitiesDetailView(APIView):
    def get(self,request,uuid):
        value = Ammenities.objects.get(uuid = uuid)
        ser = AmmenitiesSerializer(value)
        return Response(ser.data)
    
    def patch(self,request,uuid):
        data = request.data
        
        if not Ammenities.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        value = Ammenities.objects.get(uuid=uuid)
        ser = AmmenitiesSerializer(value,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)
            
    def delete(self, request, uuid):
        
        snippet = Ammenities.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})
      
class ClassByDate(APIView):
    def daterange(self,date1, date2):
        for n in range(int((date2 - date1).days) + 1):
            yield date1 + timedelta(n)
    def get(self,request):
        
        data=request.GET
        c = Classes.objects.filter(gym= data.get('gym'),instructor_info=data.get('ins'))
        date_slots = []
        for i in c:
            ser = ClassSerializer(i).data
            days=[]
            for clas in  i.class_scheduled_on.all():
                days.append(int(clas.int_day))
            start_dt = date.today()
            end_dt = start_dt + timedelta(30)
            for dt in self.daterange(start_dt, end_dt):
                if not Holiday.objects.filter(start_date=dt).exists():
                    d = dt.strftime('%d %b %Y')
                    booked_date = datetime.strptime(d,'%d %b %Y')
                    # day = dt.strftime('%A')
                    if dt.weekday() in days:
                        remain_pass = UserClass.objects.filter(gym= data.get('gym'),select_classes=i,booked_date=booked_date)
                        participants = remain_pass.count()
                        date_slots.append({"date": d,"data":ser,"participants":participants})
                        
                        # if UserClass.objects.filter(select_classes=i,booked_date=booked_date).exists():
                        #     remain_pass = UserClass.objects.filter(gym= data.get('gym'),select_classes=i,booked_date=booked_date)
                        #     for ins in remain_pass:
                        #         date_slots.append({"remain_pass":ins.seat_available})


                
        return Response(date_slots)

class GymList(generics.ListAPIView):
    queryset = GymProfile.objects.all()
    serializer_class = GymProfileSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['gym_name', 'city','about', 'address','gender_criteria','opening_days__day','classes__level']

class ClassesList(generics.ListAPIView):
    # import pdb ; pdb.set_trace()
    queryset = Classes.objects.all()
    serializer_class = ClassListSer
    filter_backends = [filters.SearchFilter]
    search_fields = ['class_topic', 'class_gender','level','gym__uuid','classes_age_group__age','select_location__gym_location','level','class_scheduled_on__day']

    def get_queryset(self):
        qset = self.queryset.filter(gym=self.request.GET.get('gym'))
        return qset

class ExpenseslistApi(APIView):
    def get(self,request):
        data = request.GET
        obj = Transaction.objects.filter(gym=data.get('gym'))
        ser = TransactionSerilaizer(obj,many = True)
        return Response(ser.data)
    def post(self,request):
        data = request.data
        
        ser = TransactionSerilaizer(data = data)
        if ser.is_valid():
            ser.save()
            return Response(ser.data)
        return Response(ser.errors)

class ExpensesDetailView(APIView):
    def get(self,request,uuid):
        
        value = Transaction.objects.get(uuid = uuid)
        ser = TransactionSerilaizer(value)
        return Response(ser.data)
    
    def patch(self,request,uuid):
        data = request.data
        
        if not Transaction.objects.filter(uuid=uuid).exists():
            return Response('Unauthorized')
        value = Transaction.objects.get(uuid=uuid)
        ser = TransactionSerilaizer(value,data=data,partial=True)
        if ser.is_valid(raise_exception=True):
            ser.save()
            return Response(('Details saved',ser.data))
        else:
            return Response(ser.errors)
            
    def delete(self, request, uuid):
        
        snippet = Transaction.objects.get(uuid = uuid)
        snippet.delete()
        return Response({'data':"Deleted"})

class Reports(APIView):
    def get(self,request):
        data = request.GET
        val= Transaction.objects.all()
        for i in val:
            ser = TransactionSerilaizer(i).data
            date = i.created_at.strftime('%Y-%m-%d')
            ser.update({
                'created_at':date
            })

        obj =  Transaction.objects.filter(created_at__lte = data.get('end_date'),created_at__gte = data.get('start_date'))
        ser = TransactionSerilaizer(obj,many=True)
        return Response(ser.data)

class Instructorclass(APIView):
    def get(self,request):
        data = request.GET
        
        context =[]
        date = data.get('date')
        booked_date = datetime.strptime(date,'%d %b %Y')
        query = UserClass.objects.filter(booked_date = booked_date,select_classes=data.get('class'),gym = data.get('gym'))
        for v in query:
            ser = UserclassSerializer(v).data
            user = v.select_user.first_name
            clas = v.select_classes.class_topic
            ser.update({
                'select_classes':clas,
                'select_user':user
            })
            context.append(ser)
        return Response(context)


def user_counts(start_date=None, end_date=None,gym=None):

    # To fetch number of users registered between given dates.....

    if start_date and end_date:
        created_at_list = list(Subscription.objects.filter(
            created_at__range=(start_date, end_date),gym=gym).values('created_at'))
    else:
        created_at_list = list(Subscription.objects.filter(
            created_at__lte=str(datetime.today()),gym=gym).values('created_at'))
    counts = len(created_at_list)
    # report = {"New Users Count": counts}
    return counts

def calc_business(start_date=None, end_date=None,gym=None):
    
    if start_date and end_date:
        orders = Subscription.objects.filter(gym=gym,created_at__range=(start_date, end_date))
        total = 0
        for o in orders:
            total+=int(o.package.package_price)
    else:
        orders = Subscription.objects.filter(gym=gym,created_at__lte=str(datetime.today()))
        total = 0
        for o in orders:
            print(o.package)
            print(o.package.package_price)
            total+=int(o.package.package_price)

    return total

def transactionReport(start_date=None, end_date=None,gym=None):

    if start_date and end_date:
        orders = Transaction.objects.filter(gym=gym,date_paid__range=(start_date, end_date))
        total = 0
        for o in orders:
            total+=int(o.transaction_amount)
    else:
        orders = Transaction.objects.filter(gym=gym,created_at__lte=str(datetime.today()))
        total = 0
        for o in orders:
            total+=int(o.transaction_amount)

    return total 

class Dashboard(APIView):

    def get(self,request):
        data=request.GET
        gym=data.get('gym_id')
        start_date = datetime.today()-timedelta(days=30)
        end_date = datetime.today()
        total_sales = calc_business(start_date, end_date,gym=gym)
        user_count = user_counts(start_date, end_date,gym=gym)
        transactions = transactionReport(start_date, end_date,gym=gym)
        
        package = UserClass.objects.filter(gym = data.get('gym_id'))
        
        context =[]
        for i in package:
            if not i.select_classes:
                context.append(i)
        package_count = len(context)

        data = {'package':package_count,'total_sales':total_sales,'transactions':transactions,'user_count':user_count}
        return Response({'data':data})
    
    
    
    # @csrf_exempt
    def post(self, request):
        data = request.data
        
        if data.get('month')=='prev':
        # curr_month = datetime.today().month
            now = datetime.now()
            last_month = now.month-1 if now.month > 1 else 12-(now.month - 1)
            year = now.year if now.month > 1 else now.year - 1
            dt = date(year, last_month, 1)
            num_days = calendar.monthrange(year, last_month)
            start_date = dt
            end_date = date(year, last_month, num_days[1] )
     
        
        elif data.get('month')=='2prev':
            now = datetime.now()-timedelta(days=60)
            num_days = calendar.monthrange(now.year, now.month)
            start_date = date(now.year, now.month, 1)
            end_date = date(now.year, now.month, num_days[1] )
            
        
        
        elif data.get('month')=='3prev':
            now = datetime.now()-timedelta(days=90)
            num_days = calendar.monthrange(now.year, now.month)
            start_date = date(now.year, now.month, 1)
            end_date = date(now.year, now.month, num_days[1] )
          


        else:
            start_date = data.get('start_date')
            end_date = data.get('end_date')
        gym = data.get('gym_id')

        total_sales = calc_business(start_date, end_date,gym=gym)
        user_count = user_counts(start_date, end_date,gym=gym)
        transactions = transactionReport(start_date, end_date,gym=gym)
        profit = int(total_sales)-int(transactions)
       
        data = {'total_sales':total_sales,'transactions':transactions,'user_count':user_count,'profit':profit}
        return Response({'data':data})

import pandas as pd

class Reports_CSV(APIView):
   def post(self,request):
        
        data = request.data

        oplist = ['total_sales','transactions','user_count','profit']
        for val in oplist:
            reports.append({val:data.get('data')[val]})

        invoices = pd.DataFrame(reports)
        invoices = invoices.to_csv('media/reportsdata.csv')
        url = 'http://127.0.0.1:8000/media/reportsdata.csv'
        return Response(url)


