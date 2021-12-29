from django.apps import AppConfig


class GymprofileConfig(AppConfig):
    name = 'gymprofile'


# def get(self,request):
        # import pdb; pdb.set_trace()
        
        
        # data = request.GET
        # month=months[data.get('month')]
        # year = int(data.get('year'))
        # # range = calendar.monthrange(year,month)

        # vlaue = Course.objects.filter(gym = data.get("gym_id"))
        # context = []
        # for i in vlaue:
        #     if i.course_start_date.year==year and i.course_start_date.month==month:#and i.course_start_date>date.today():
        #         context.append(i.uuid)
                
        # return Response(context)