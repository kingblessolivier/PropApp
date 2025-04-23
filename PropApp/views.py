import paypalrestsdk
from django.contrib.auth import login, authenticate, logout
from django.db.models import Sum
from django.http import HttpResponse
from .forms import TenantProfileForm
from django.views.decorators.csrf import csrf_exempt
from .models import Lease, Payment, MaintenanceRequest, Message, LikedProperties, Visit
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from django.utils.timezone import now, timedelta
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import CustomerMessage, Owner, User, Updates, CustRequest
from django.utils import timezone
from .serializers import *
from django.shortcuts import get_object_or_404, redirect
from django.core.mail import send_mail
from django.contrib import messages
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required, user_passes_test
import os
from django.shortcuts import render
from django.conf import settings

def is_admin(user):
    return user.is_authenticated and user.role == 'Admin'


@csrf_exempt
@api_view(['GET', 'POST', 'DELETE'])
def properties(request):
    if request.method == 'GET':
        property_list = Property.objects.all()
        serializer = PropertySerializer(property_list, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = PropertySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)
    elif request.method == 'DELETE':
        Property.objects.all().delete()
        return Response(status=204)


@csrf_exempt
@api_view(['GET', 'PUT', 'DELETE'])
def property_details(request, pk):
    try:
        property = Property.objects.get(pk=pk)
    except Property.DoesNotExist:
        return Response(status=404)

    if request.method == 'GET':
        serializer = PropertySerializer(property)
        return Response(serializer.data)
    elif request.method == 'PUT':
        serializer = PropertySerializer(property, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)
    elif request.method == 'DELETE':
        property.delete()
        return Response(status=204)


@csrf_exempt
@api_view(['GET', 'POST', 'DELETE'])
def tenants(request):
    if request.method == 'GET':
        tenant_list = Tenant.objects.all()
        serializer = TenantSerializer(tenant_list, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = TenantSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)
    elif request.method == 'DELETE':
        Tenant.objects.all().delete()
        return Response(status=204)


@csrf_exempt
@api_view(['GET', 'PUT', 'DELETE'])
def tenant_details(request, pk):
    try:
        tenant = Tenant.objects.get(pk=pk)
    except Tenant.DoesNotExist:
        return Response(status=404)

    if request.method == 'GET':
        serializer = TenantSerializer(tenant)
        return Response(serializer.data)
    elif request.method == 'PUT':
        serializer = TenantSerializer(tenant, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)
    elif request.method == 'DELETE':
        tenant.delete()
        return Response(status=204)


@csrf_exempt
@api_view(['GET', 'POST', 'DELETE'])
def units(request):
    if request.method == 'GET':
        unit_list = Unit.objects.all()
        serializer = UnitSerializer(unit_list, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = UnitSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)
    elif request.method == 'DELETE':
        Unit.objects.all().delete()
        return Response(status=204)


@csrf_exempt
@api_view(['GET', 'PUT', 'DELETE'])
def unit_details(request, pk):
    try:
        unit = Unit.objects.get(pk=pk)
    except Unit.DoesNotExist:
        return Response(status=404)

    if request.method == 'GET':
        serializer = UnitSerializer(unit)
        return Response(serializer.data)
    elif request.method == 'PUT':
        serializer = UnitSerializer(unit, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)
    elif request.method == 'DELETE':
        unit.delete()
        return Response(status=204)


@csrf_exempt
@api_view(['GET', 'POST', 'DELETE'])
def leases(request):
    if request.method == 'GET':
        lease_list = Lease.objects.all()
        serializer = LeaseSerializer(lease_list, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = LeaseSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)
    elif request.method == 'DELETE':
        Lease.objects.all().delete()
        return Response(status=204)


@csrf_exempt
@api_view(['GET', 'PUT', 'DELETE'])
def lease_details(request, pk):
    try:
        lease = Lease.objects.get(pk=pk)
    except Lease.DoesNotExist:
        return Response(status=404)
    if request.method == 'GET':
        serializer = LeaseSerializer(lease)
        return Response(serializer.data)
    elif request.method == 'PUT':
        serializer = LeaseSerializer(lease, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)
    elif request.method == 'DELETE':
        lease.delete()
        return Response(status=204)


@csrf_exempt
def index(request):
    user = request.user.id
    owner_user = Owner.objects.filter(user_id=user).exists()
    tenant_user = Tenant.objects.filter(user_id=user).exists()
    featured_properties = Property.objects.all().order_by('-date_added')[:3]
    tenant = Tenant.objects.all()
    property = Property.objects.all()
    context = {
        'owner_user': owner_user,
        'tenant': tenant,
        'property': property,
        'featured_properties': featured_properties,
        'tenant_user': tenant_user,
    }
    return render(request, 'home/home.html', context)


@csrf_exempt
def property_list(request):
    property_list = Property.objects.all()
    context = {'property_list': property_list}
    if search := request.GET.get('search'):
        query = Property.objects.filter(name__icontains=search)
        context['property_list'] = query
        context['search'] = search
        num_results = len(query)
        context['num_results'] = num_results
    else:
        num_results = len(property_list)
        context['num_results'] = num_results

    return render(request, 'home/properties.html', context)


@csrf_exempt
def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            if user.role == 'Admin':
                return redirect('index')
            elif user.role == 'Owner':
                return redirect('index')
            elif user.role == 'Tenant':
                return redirect('index')
        else:
            if User.objects.filter(username=username).exists() and not User.objects.get(username=username).is_active:
                messages.error(request, 'Account is not active. Please contact admin')
                return redirect('user_login')
            elif User.objects.filter(username=username).exists() and User.objects.get(username=username).is_active:
                messages.error(request, 'Password is incorrect')
                return redirect('user_login')
            else:
                messages.error(request, 'Credentials you provided is not familiar with us. Please try again')
                return redirect('user_login')
    else:
        return render(request, 'home/Login.html')


@csrf_exempt
def user_logout(request):
    logout(request)
    return redirect('index')


@csrf_exempt
def register(request):
    return render(request, 'home/Register.html')


@csrf_exempt
def user_register(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        email = request.POST['email']
        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return redirect('register')
        elif User.objects.filter(email=email).exists():
            messages.error(request, 'Email already exists')
            return redirect('register')
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            user.save()
            messages.success(request, 'Account created successfully')
            return redirect('user_login')
    else:
        return render(request, 'home/Register.html')


@csrf_exempt
def about(request):
    return render(request, 'home/about.html')


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='../')
def admin_dashboard(request):
    total_enquiries = CustRequest.objects.filter(is_read=False).count()
    property_list = Property.objects.all()
    property_total = Property.objects.all().count()
    owner_list = Owner.objects.all()
    owner_total = Owner.objects.all().count()
    tenant_list = Tenant.objects.all()
    tenant_total = Tenant.objects.all().count()
    message_list = CustomerMessage.objects.filter(is_read=False)
    message_total = message_list.count()
    all_messages = CustomerMessage.objects.all()
    read_messages = CustomerMessage.objects.filter(is_read=True)
    unread_messages = CustomerMessage.objects.filter(is_read=False)
    read_enquiries = CustRequest.objects.filter(is_read=True).count()
    unread_enquiries = CustRequest.objects.filter(is_read=False).count()
    archived_enquiries = CustRequest.objects.filter(is_archived=True).count()
    today = now().date()
    last_7_days = [today - timedelta(days=i) for i in range(6, -1, -1)]

    daily_data = [
        {'date': day, 'count': User.objects.filter(date_joined__date=day).count()}
        for day in last_7_days
    ]

    context = {
        'property_list': property_list,
        'property_total': property_total,
        'owner_list': owner_list,
        'owner_total': owner_total,
        'tenant_list': tenant_list,
        'tenant_total': tenant_total,
        'message_list': message_list,
        'message_total': message_total,
        'all_messages': all_messages,
        'read_messages': read_messages,
        'unread_messages': unread_messages,
        'total_enquiries': total_enquiries,
        'unread_enquiries': unread_enquiries,
        'archived_enquiries': archived_enquiries,
        'read_enquiries': read_enquiries,
        'daily_user_registration_dates': [data['date'].strftime('%Y-%m-%d') for data in daily_data],
        'daily_user_registration_counts': [data['count'] for data in daily_data]
    }
    return render(request, 'admin/admin_base/dashboard.html', context)


@csrf_exempt
def contact(request):
    return render(request, 'home/contact.html')


@csrf_exempt
def updates(request):
    updates = Updates.objects.filter(end_date__gte=now()).order_by('-created_at')
    context = {'updates': updates}
    return render(request, 'home/updates.html', context)


@csrf_exempt
def property_lists(request):
    property_lists = Property.objects.all()
    context = {'property_lists': property_lists}
    if search := request.GET.get('search'):
        query = Property.objects.filter(name__icontains=search)
        context['property_list'] = query
        context['search'] = search
        num_results = len(query)
        context['num_results'] = num_results
    else:
        num_results = len(property_lists)
        context['num_results'] = num_results
    return render(request, 'admin/admin_base/admin.html', context)


@csrf_exempt
def tenant_list(request):
    tenant_list = Tenant.objects.all()
    context = {'tenant_list': tenant_list}
    if search := request.GET.get('search'):
        context['search'] = search
        query = Tenant.objects.filter(name__icontains=search)
        context['tenant_list'] = query
        num_results = len(query)
        context['num_results'] = num_results
    else:
        num_results = len(tenant_list)
        context['num_results'] = num_results
    return render(request, 'admin/admin_base/admin.html', context)


@csrf_exempt
def message_list(request):
    message_list = CustomerMessage.objects.all()
    context = {'message_list': message_list}
    if search := request.GET.get('search'):
        context['search'] = search
        query = CustomerMessage.objects.filter(name__icontains=search)
        context['message_list'] = query
        num_results = len(query)
        context['num_results'] = num_results
    else:
        num_results = len(message_list)
        context['num_results'] = num_results
    return render(request, 'admin/admin_base/admin.html', context)


@csrf_exempt
def owner_list(request):
    owner_list = User.objects.filter(role='Owner')
    context = {'owner_list': owner_list}
    if search := request.GET.get('search'):
        context['search'] = search
        query = User.objects.filter(username__icontains=search, role='Owner')
        context['owner_list'] = query
        num_results = len(query)
        context['num_results'] = num_results
    else:
        num_results = len(owner_list)
        context['num_results'] = num_results
    return render(request, 'admin/admin_base/admin.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def totals(request):
    property_total = Property.objects.all().count()
    tenant_total = Tenant.objects.all().count()
    unit_total = Unit.objects.all().count()
    lease_total = Lease.objects.all().count()
    message_total = CustomerMessage.objects.all().count()
    context = {
        'property_total': property_total,
        'tenant_total': tenant_total,
        'unit_total': unit_total,
        'lease_total': lease_total,
        'message_total': message_total
    }
    return render(request, 'admin/admin_base/admin.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def delete_property(request, id):
    property = Property.objects.get(id=id)
    property.delete()
    messages.success(request, 'Property deleted successfully')
    return redirect('admin_properties')


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def add_property(request):
    owner_list = Owner.objects.all()

    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            address = request.POST.get('address')
            types = request.POST.get('property_type')
            description = request.POST.get('description')
            number_of_units = request.POST.get('number_of_units')
            price = request.POST.get('price')
            image = request.FILES.get('image')
            owner_id = request.POST.get('owner')

            property_instance = Property.objects.create(
                name=name,
                address=address,
                types=types,
                description=description,
                price=price,
                image=image,
                number_of_units=number_of_units,
                owner_id=owner_id,
            )

            unit_numbers = request.POST.getlist('unit_number[]')
            bedrooms = request.POST.getlist('bedrooms[]')
            bathrooms = request.POST.getlist('bathrooms[]')
            rents = request.POST.getlist('rent[]')
            availabilities = request.POST.getlist('is_available[]')

            if not (len(unit_numbers) == len(bedrooms) == len(bathrooms) == len(rents)):
                messages.error(request, 'Mismatched number of unit details submitted.')
                return redirect('add_property')

            for i in range(len(unit_numbers)):
                Unit.objects.create(
                    property=property_instance,
                    unit_number=unit_numbers[i],
                    bedrooms=bedrooms[i],
                    bathrooms=bathrooms[i],
                    rent=rents[i],
                    is_available=availabilities[i] == 'on' if availabilities[i] else False
                )

            messages.success(request, 'Property added successfully')
            return redirect('admin_properties')
        except Exception as e:
            messages.error(request, f'Error adding property: {e}')
            return redirect('add_property')

    return render(request, 'admin/properties/add_property.html', {'owner_list': owner_list})


@csrf_exempt
def property_view(request, id):
    try:
        property = Property.objects.get(id=id)
    except Property.DoesNotExist:
        messages.error(request, 'Property not found')
        return redirect('property_list')

    user = request.user
    if user.is_authenticated:
        liked_properties = LikedProperties.objects.filter(user=user, property=property).exists()
        tenant_visits = Visit.objects.filter(property=property).exists()
    else:
        liked_properties = False
        tenant_visits = False
    featured_properties = Property.objects.all().order_by('-date_added')[:6]
    context = {
        'property': property,
        'liked_properties': liked_properties,
        'tenant_visits': tenant_visits,
        'featured_properties': featured_properties
    }
    return render(request, 'home/details.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def admin_properties(request):
    properties = Property.objects.all()
    property_total = Property.objects.all().count()
    owner_list = Owner.objects.all()
    owner_total = Owner.objects.all().count()
    tenant_list = Tenant.objects.all()
    tenant_total = Tenant.objects.all().count()
    message_list = CustomerMessage.objects.filter(is_read=False)
    message_total = message_list.count()
    type_list = Property.objects.values_list('types', flat=True).distinct()
    paginator = Paginator(properties, 10)
    page_number = request.GET.get('page')
    properties = paginator.get_page(page_number)
    context = {
        'properties': properties,
        'property_total': property_total,
        'owner_list': owner_list,
        'owner_total': owner_total,
        'tenant_list': tenant_list,
        'tenant_total': tenant_total,
        'message_list': message_list,
        'message_total': message_total,
        'type_list': type_list
    }

    query = request.GET.get('search')
    property_type = request.GET.get('type')
    owner_id = request.GET.get('owner')
    search_query = request.GET.get('search')

    if property_type:
        properties = Property.objects.filter(types=property_type)
        context['property_type'] = property_type
    if owner_id:
        properties = Property.objects.filter(owner_id=owner_id)
        context['owner_id'] = owner_id

    if search_query:
        if search_query.isdigit():
            properties = Property.objects.filter(price__lte=search_query)
            context['search_query'] = search_query
        else:
            properties = Property.objects.filter(address__icontains=search_query)
            context['search_query'] = search_query
    context['properties'] = properties
    num_results = len(properties)
    context['num_results'] = num_results
    return render(request, 'admin/properties/properties.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def adding_property(request):
    properties = Property.objects.all()
    property_total = Property.objects.all().count()
    owner_list = Owner.objects.all()
    owner_total = Owner.objects.all().count()
    tenant_list = Tenant.objects.all()
    tenant_total = Tenant.objects.all().count()
    message_list = CustomerMessage.objects.filter(is_read=False)
    message_total = message_list.count()
    context = {
        'properties': properties,
        'property_total': property_total,
        'owner_list': owner_list,
        'owner_total': owner_total,
        'tenant_list': tenant_list,
        'tenant_total': tenant_total,
        'message_list': message_list,
        'message_total': message_total
    }
    search = request.GET.get('search')

    return render(request, 'admin/properties/add_property.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def editing_property(request, id):
    property = Property.objects.get(id=id)
    owner_list = Owner.objects.all()
    context = {'property': property, 'owner_list': owner_list}
    return render(request, 'admin/properties/edit_property.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def edit_property(request, id):
    property_instance = get_object_or_404(Property, id=id)

    if request.method == 'POST':
        property_instance.name = request.POST['name']
        property_instance.address = request.POST['address']
        property_instance.types = request.POST['type']
        property_instance.price = request.POST['price']
        property_instance.description = request.POST['description']
        property_instance.owner_id = request.POST['owner_id']
        property_instance.number_of_units = request.POST['number_of_units']
        property_instance.status = request.POST['status']

        if 'image' in request.FILES:
            property_instance.image = request.FILES['image']

        property_instance.save()
        messages.success(request, 'Property updated successfully!')
        return redirect('admin_properties')

    return render(request, 'admin/properties/edit_property.html', {'property': property_instance})


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def admin_users(request):
    users = User.objects.all()
    user_total = users.count()
    property_list = Property.objects.all()
    property_total = property_list.count()
    owner_list = Owner.objects.all()
    owner_total = owner_list.count()
    tenant_list = Tenant.objects.all()
    tenant_total = tenant_list.count()
    message_list = CustomerMessage.objects.filter(is_read=False)
    message_total = message_list.count()
    role_list = User.objects.values_list('role', flat=True).distinct()
    status_list = User.objects.values_list('is_active', flat=True).distinct()
    paginator = Paginator(users, 7)
    page_number = request.GET.get('page')
    users = paginator.get_page(page_number)
    context = {
        'users': users,
        'user_total': user_total,
        'total_users': User.objects.count(),
        'property_list': property_list,
        'property_total': property_total,
        'owner_list': owner_list,
        'owner_total': owner_total,
        'tenant_list': tenant_list,
        'tenant_total': tenant_total,
        'message_list': message_list,
        'message_total': message_total,
        'role_list': role_list,
        'status_list': status_list
    }

    role = request.GET.get('role')
    status = request.GET.get('status')
    search_query = request.GET.get('search')

    if role:
        users = users.filter(role=role)
        context['role'] = role
        context['users'] = users

    if status:
        users = users.filter(is_active=status)
        context['status'] = status
        context['users'] = users

    if search_query:
        users = users.filter(username__icontains=search_query)
        context['search_query'] = search_query
        context['users'] = users
        context['num_results'] = users.count()

    return render(request, 'admin/users/users.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def adding_user(request):
    users = User.objects.all()
    user_total = User.objects.all().count()
    property_list = Property.objects.all()
    property_total = Property.objects.all().count()
    owner_list = Owner.objects.all()
    owner_total = Owner.objects.all().count()
    tenant_list = Tenant.objects.all()
    tenant_total = Tenant.objects.all().count()
    message_list = CustomerMessage.objects.filter(is_read=False)
    message_total = message_list.count()
    context = {
        'users': users,
        'user_total': user_total,
        'property_list': property_list,
        'property_total': property_total,
        'owner_list': owner_list,
        'owner_total': owner_total,
        'tenant_list': tenant_list,
        'tenant_total': tenant_total,
        'message_list': message_list,
        'message_total': message_total
    }
    return render(request, 'admin/users/add_users.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def editing_user(request, id):
    user = User.objects.get(id=id)
    context = {'user': user}
    return render(request, 'admin/users/edit_user.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def edit_user(request, id):
    user = get_object_or_404(User, id=id)

    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        role = request.POST.get('role')
        join_date = request.POST.get('join_date')
        is_active = 'is_active' in request.POST
        is_staff = 'is_staff' in request.POST

        if password and password == confirm_password:
            user.set_password(password)
        elif password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('edit_user', user_id=user.id)

        user.username = username
        user.email = email
        user.is_active = is_active
        user.role = role
        user.is_staff = is_staff
        user.date_joined = timezone.datetime.strptime(join_date, '%Y-%m-%d')
        user.save()

        messages.success(request, "User details updated successfully.")
        return redirect('admin_users')

    return render(request, 'admin/users/edit_user.html', {'user': user})


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def add_user(request):
    try:
        if request.method == 'POST':
            username = request.POST['username']
            email = request.POST['email']
            password = request.POST['password']
            confirm_password = request.POST['confirm_password']
            role = request.POST['role']
            join_date = request.POST['join_date']
            is_active = 'is_active' in request.POST
            is_staff = 'is_staff' in request.POST

            if password and password == confirm_password:
                user = User.objects.create_user(username=username, email=email, password=password, role=role, is_active=is_active, is_staff=is_staff, date_joined=join_date)
                user.save()
                messages.success(request, 'User added successfully!')
                return redirect('admin_users')
            elif password != confirm_password:
                messages.error(request, "Passwords do not match.")
                return redirect('add_user')
            else:
                messages.error(request, "Error adding user.")
                return redirect('add_user')
        return render(request, 'admin/users/add_users.html')
    except Exception as e:
        messages.error(request, "Error occurred while adding user.")
        return redirect('adding_user')


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def delete_user(request, id):
    user = User.objects.get(id=id)
    if user.is_superuser:
        messages.error(request, 'You can\'t delete this user')
        return redirect('admin_users')
    else:
        user.delete()
        messages.success(request, 'User deleted successfully')
        return redirect('admin_users')


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def disapprove_user(request, id):
    user = User.objects.get(id=id)
    if user.role == 'Admin':
        messages.error(request, 'Admin cannot be deactivated')
        return redirect('admin_users')
    elif user.is_superuser:
        messages.error(request, 'Superuser cannot be deactivated')
    else:
        user.is_active = False
        user.save()
        messages.success(request, 'User deactivated successfully')
    return redirect('admin_users')


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def approve_user(request, id):
    user = User.objects.get(id=id)
    if user.role == 'Admin':
        messages.error(request, 'Admin cannot be activated')
        return redirect('admin_users')
    elif user.is_superuser:
        messages.error(request, 'Superuser cannot be activated')
    else:
        user.is_active = True
        user.save()
    messages.success(request, 'User activated successfully')
    return redirect('admin_users')


@csrf_exempt
def admin_owners(request):
    owners = Owner.objects.all()
    owner_total = owners.count()
    property_list = Property.objects.all()
    property_total = property_list.count()
    tenant_list = Tenant.objects.all()
    tenant_total = tenant_list.count()
    message_list = CustomerMessage.objects.filter(is_read=False)
    message_total = message_list.count()
    search_query = request.GET.get('search', '')
    if search_query:
        owners = owners.filter(name__icontains=search_query) | owners.filter(email__icontains=search_query)

    paginator = Paginator(owners, 10)
    page_number = request.GET.get('page')
    owners = paginator.get_page(page_number)
    context = {
        'owners': owners,
        'owner_total': owner_total,
        'property_list': property_list,
        'property_total': property_total,
        'tenant_list': tenant_list,
        'tenant_total': tenant_total,
        'message_list': message_list,
        'message_total': message_total
    }
    return render(request, 'admin/owners/owners.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def adding_owner(request):
    user_list = User.objects.all()
    used_users = Owner.objects.values_list('user', flat=True)
    available_users = User.objects.exclude(id__in=used_users)
    user_total = User.objects.all().count()
    owners = Owner.objects.all()
    owner_total = Owner.objects.all().count()
    property_list = Property.objects.all()
    property_total = Property.objects.all().count()
    tenant_list = Tenant.objects.all()
    tenant_total = Tenant.objects.all().count()
    message_list = CustomerMessage.objects.filter(is_read=False)
    message_total = message_list.count()

    context = {
        'owners': owners,
        'owner_total': owner_total,
        'property_list': property_list,
        'property_total': property_total,
        'tenant_list': tenant_list,
        'tenant_total': tenant_total,
        'message_list': message_list,
        'message_total': message_total,
        'user_list': user_list,
        'user_total': user_total,
        'available_users': available_users,
        'used_users': used_users,
    }

    search = request.GET.get('search')
    if search:
        query = Owner.objects.filter(name__icontains=search)
        context['search'] = search
        context['owners'] = query
    return render(request, 'admin/owners/add_owner.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def add_owner(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        phone = request.POST['phone_number']
        address = request.POST['address']
        user_id = request.POST['user_id']
        image = request.FILES['image']
        new_owner = Owner.objects.create(
            name=name,
            email=email,
            phone_number=phone,
            address=address,
            user_id=user_id,
            image=image
        )
        new_owner.save()
        messages.success(request, 'Owner added successfully!')
        return redirect('admin_owners')
    return render(request, 'admin/owners/add_owner.html')


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def editing_owner(request, id):
    owner = Owner.objects.get(id=id)
    available_users = User.objects.exclude(id=owner.user_id)
    used_users = Owner.objects.values_list('user', flat=True)

    context = {'owner': owner, 'available_users': available_users, 'used_users': used_users}
    return render(request, 'admin/owners/edit_owner.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def edit_owner(request, id):
    owner = get_object_or_404(Owner, id=id)
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        address = request.POST.get('address')
        user_id = request.POST.get('user_id')
        image = request.FILES.get('image')
        if image:
            owner.image = image
        owner.name = name
        owner.email = email
        owner.phone = phone
        owner.user = user_id
        owner.address = address
        owner.save()
        messages.success(request, 'Owner details updated successfully.')
        return redirect('admin_owners')
    return render(request, 'admin/owners/edit_owner.html', {'owner': owner})


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def delete_owner(request, id):
    owner = Owner.objects.get(id=id)
    owner.delete()
    messages.success(request, 'Owner deleted successfully')
    return redirect('admin_owners')


@csrf_exempt
def admin_updates(request):
    updates = Updates.objects.all()
    update_total = updates.count()
    property_list = Property.objects.all()
    property_total = property_list.count()
    owner_list = Owner.objects.all()
    owner_total = owner_list.count()
    tenant_list = Tenant.objects.all()
    tenant_total = tenant_list.count()
    message_list = CustomerMessage.objects.filter(is_read=False)
    message_total = message_list.count()
    context = {
        'updates': updates,
        'update_total': update_total,
        'property_list': property_list,
        'property_total': property_total,
        'owner_list': owner_list,
        'owner_total': owner_total,
        'tenant_list': tenant_list,
        'tenant_total': tenant_total,
        'message_list': message_list,
        'message_total': message_total
    }
    search = request.GET.get('search')
    if search:
        query = Updates.objects.filter(title__icontains=search)
        context['search'] = search
        context['updates'] = query
    return render(request, 'admin/updates/updates.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def adding_update(request):
    property_list = Property.objects.all()
    property_total = property_list.count()
    owner_list = Owner.objects.all()
    owner_total = owner_list.count()
    tenant_list = Tenant.objects.all()
    tenant_total = tenant_list.count()
    message_list = CustomerMessage.objects.filter(is_read=False)
    message_total = message_list.count()
    context = {
        'property_list': property_list,
        'property_total': property_total,
        'owner_list': owner_list,
        'owner_total': owner_total,
        'tenant_list': tenant_list,
        'tenant_total': tenant_total,
        'message_list': message_list,
        'message_total': message_total
    }

    return render(request, 'admin/updates/add_update.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def add_update(request):
    if request.method == 'POST':
        title = request.POST['title']
        description = request.POST['description']
        created_at = request.POST['created_at']
        end_date = request.POST['end_date']
        updates = Updates.objects.create(title=title, description=description, created_at=created_at, end_date=end_date)
        updates.save()
        messages.success(request, 'Update added successfully!')
        return redirect('admin_updates')
    return render(request, 'admin/updates/add_update.html')


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def editing_update(request, id):
    update = Updates.objects.get(id=id)
    context = {'update': update}
    return render(request, 'admin/updates/edit_update.html', context)


@csrf_exempt
@login_required(login_url='user_login')
@user_passes_test(is_admin, login_url='user_login')
def edit_update(request, id):
    update = get_object_or_404(Updates, id=id)
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        created_at = request.POST.get('created_at')
        end_date = request.POST.get('end_date')
        update.title = title
        update.description = description
        update.created_at = created_at
        update.end_date = end_date
        update.save()
        messages.success(request, 'Update details updated successfully.')
        return redirect('admin_updates')
    return render(request, 'admin/updates/edit_update.html', {'update': update})


@csrf_exempt
def delete_update(request, id):
    update = Updates.objects.get(id=id)
    update.delete()
    messages.success(request, 'Update deleted successfully')
    return redirect('admin_updates')


@csrf_exempt
def message_list_view(request):
    unread_messages = CustomerMessage.objects.filter(is_read=False).order_by('-created_at')
    read_messages = CustomerMessage.objects.filter(is_read=True, is_archived=False).order_by('-created_at')
    archived_messages = CustomerMessage.objects.filter(is_archived=True, is_read=True).order_by('-created_at')
    category_list = CustomerMessage.objects.all()
    message_total = unread_messages.count()
    total_enquiries = CustRequest.objects.filter(is_read=False).count()
    paginator = Paginator(category_list, 10)
    page_number = request.GET.get('page')
    messages = paginator.get_page(page_number)

    context = {
        'unread_messages': unread_messages,
        'read_messages': read_messages,
        'archived_messages': archived_messages,
        'message_total': message_total,
        'category_list': category_list,
        'total_enquiries': total_enquiries
    }
    return render(request, 'admin/messages/messages.html', context)


@csrf_exempt
def mark_as_read_view(request, message_id):
    message = get_object_or_404(CustomerMessage, id=message_id)
    if not message.is_read:
        message.is_read = True
        message.created_at = timezone.now()
        message.save()
    return redirect('message_list')


@csrf_exempt
def delete_message_view(request, message_id):
    message = get_object_or_404(CustomerMessage, id=message_id)
    message.delete()
    return redirect('message_list')


@csrf_exempt
def archive_message_view(request, message_id):
    message = get_object_or_404(CustomerMessage, id=message_id)
    if not message.is_archived:
        message.is_archived = True
        message.created_at = timezone.now()
        message.save()
    return redirect('message_list')


@csrf_exempt
def customer_message(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        message_content = request.POST['message']
        message = CustomerMessage.objects.create(name=name, email=email, message=message_content)
        message.save()
        messages.success(request, 'Message sent successfully!')
        return redirect('contact')
    return render(request, 'home/contact.html')


@csrf_exempt
def send_email(request):
    if request.method == 'POST':
        sender_email = request.POST['sender_email']
        recipient_email = request.POST['recipient_email']
        subject = request.POST['subject']
        body = request.POST['body']
        send_mail(subject, body, sender_email, [recipient_email])
        messages.success(request, 'Email sent successfully!')
        return redirect('message_list')
    return render(request, 'admin/messages/reply.html')


@csrf_exempt
def mail(request, message_id):
    message = get_object_or_404(CustomerMessage, id=message_id)
    context = {'message': message}
    return render(request, 'admin/messages/reply.html', context)


@csrf_exempt
def read_message(request, message_id):
    message = get_object_or_404(CustomerMessage, id=message_id)
    return render(request, 'admin/messages/message_body.html', {'message': message})


@csrf_exempt
def admin_tenants(request):
    tenants = Tenant.objects.all()
    tenant_total = tenants.count()
    property_list = Property.objects.all()
    property_total = property_list.count()
    owner_list = Owner.objects.all()
    owner_total = owner_list.count()
    message_list = CustomerMessage.objects.filter(is_read=False)
    message_total = message_list.count()
    context = {
        'tenants': tenants,
        'tenant_total': tenant_total,
        'property_list': property_list,
        'property_total': property_total,
        'owner_list': owner_list,
        'owner_total': owner_total,
        'message_list': message_list,
        'message_total': message_total
    }
    search = request.GET.get('search')
    if search:
        query = Tenant.objects.filter(name__icontains=search)
        context['search'] = search
        context['tenants'] = query

    return render(request, 'admin/tenants/tenants.html', context)


@csrf_exempt
def delete_tenant(request, tenant_id):
    if request.method == "POST":
        tenant = get_object_or_404(Tenant, id=tenant_id)
        tenant.delete()
        return redirect('admin_tenants')


@csrf_exempt
def manage_leases(request):
    leases = Lease.objects.all()
    unsigned_leases = leases.filter(status='unsigned')
    signed_leases = leases.filter(status='signed')
    archived_leases = leases.filter(status='archived')

    context = {
        'leases': leases,
        'unsigned_leases': unsigned_leases,
        'signed_leases': signed_leases,
        'archived_leases': archived_leases,
    }
    return render(request, 'manage_leases.html', context)


@csrf_exempt
def lease_details(request, lease_id):
    lease = get_object_or_404(Lease, id=lease_id)
    return render(request, 'lease_details.html', {'lease': lease})


@csrf_exempt
def sign_lease(request, lease_id):
    lease = get_object_or_404(Lease, id=lease_id)
    lease.status = 'signed'
    lease.save()
    messages.success(request, 'Lease marked as signed.')
    return redirect('manage_leases')


@csrf_exempt
def delete_lease(request, lease_id):
    lease = get_object_or_404(Lease, id=lease_id)
    lease.delete()
    messages.success(request, 'Lease deleted successfully.')
    return redirect('manage_leases')


@csrf_exempt
def archive_lease(request, lease_id):
    lease = get_object_or_404(Lease, id=lease_id)
    lease.status = 'archived'
    lease.save()
    messages.success(request, 'Lease archived successfully.')
    return redirect('manage_leases')


@csrf_exempt
def admin_inquiries(request):
    all_enquiries = CustRequest.objects.all()
    read_enquiries = CustRequest.objects.filter(is_read=True, is_archived=False).order_by('-created_at')
    unread_enquires = CustRequest.objects.filter(is_read=False, is_archived=False).order_by('-created_at')
    archived_enquiries = CustRequest.objects.filter(is_archived=True, is_read=True).order_by('-created_at')
    total_enquiries = CustRequest.objects.filter(is_read=False).count()
    message_list = CustomerMessage.objects.filter(is_read=False)
    message_total = message_list.count()

    context = {
        'all_enquiries': all_enquiries,
        'read_enquiries': read_enquiries,
        'unread_enquires': unread_enquires,
        'archived_enquiries': archived_enquiries,
        'total_enquiries': total_enquiries,
        'message_total': message_total,
    }
    return render(request, 'admin/Customer_Enquires/customer_enquires.html', context)


@csrf_exempt
def viewEnquiry(request, pk):
    enquiry = get_object_or_404(CustRequest, id=pk)
    context = {'enquiry': enquiry}
    return render(request, 'admin/Customer_Enquires/enquiry_body.html', context)


@csrf_exempt
def mark_as_read_enquiry(request, pk):
    enquiry = get_object_or_404(CustRequest, id=pk)
    if not enquiry.is_read:
        enquiry.is_read = True
        enquiry.created_at = timezone.now()
        enquiry.save()
        return redirect('admin_inquiries')


@csrf_exempt
def delete_enquiry(request, pk):
    enquiry = get_object_or_404(CustRequest, id=pk)
    enquiry.delete()
    return redirect('admin_inquiries')


@csrf_exempt
def archive_enquiry(request, pk):
    enquiry = get_object_or_404(CustRequest, id=pk)
    if not enquiry.is_archived:
        enquiry.is_archived = True
        enquiry.created_at = timezone.now()
        enquiry.save()
        return redirect('admin_inquiries')


@csrf_exempt
def customer_enquiry(request, id):
    if request.method == 'POST':
        property = get_object_or_404(Property, id=id)
        name = request.POST['name']
        email = request.POST['email']
        message = request.POST['enquiry']
        enquiry = CustRequest.objects.create(property=property, name=name, email=email, message=message)
        enquiry.save()
        messages.success(request, 'Enquiry sent successfully!')
        return redirect('property_view', id=id)
    return render(request, 'home/details.html')


@csrf_exempt
def unarchive_enquiry(request, pk):
    enquiry = get_object_or_404(CustRequest, id=pk)
    enquiry.is_archived = False
    enquiry.save()
    return redirect('admin_inquiries')


@csrf_exempt
def send_enquiry_email(request):
    if request.method == 'POST':
        sender_email = request.POST['sender_email']
        recipient_email = request.POST['recipient_email']
        subject = request.POST['subject']
        body = request.POST['body']
        send_mail(subject, body, sender_email, [recipient_email])
        messages.success(request, 'Email sent successfully!')
        return redirect('message_list')
    return render(request, 'admin/Customer_Enquires/reply.html')


@csrf_exempt
def mail_enquiry(request, id):
    enquiry = get_object_or_404(CustRequest, id=id)
    context = {'enquiry': enquiry}
    return render(request, 'admin/Customer_Enquires/reply.html', context)


@csrf_exempt
@login_required
@user_passes_test(is_admin)
def make_owner(request, user_id):
    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        user.role = 'Owner'  # Adjust based on how you store roles
        user.save()
        messages.success(request, 'User made Owner successfully.')
        return redirect('admin_users')

    return render(request, 'admin/users/users.html', {'user': user})


@csrf_exempt
@login_required
@user_passes_test(is_admin)
def make_admin(request, user_id):
    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        user.role = 'Admin'  # Adjust based on how you store roles
        user.save()
        messages.success(request, 'User made Admin successfully.')
        return redirect('admin_users')

    return render(request, 'admin/users/users.html', {'user': user})


@csrf_exempt
def unmake_owner(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.role = 'Tenant'  # Adjust based on how you store roles
    user.save()
    messages.success(request, 'User made Tenant successfully.')
    return redirect('admin_users')


@csrf_exempt
def unmake_admin(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.role = 'Tenant'  # Adjust based on how you store roles
    user.save()
    messages.success(request, 'User made Tenant successfully.')
    return redirect('admin_users')


@csrf_exempt
def owner_dashboard(request, user_id):
    user = get_object_or_404(User, id=user_id)
    owner = get_object_or_404(Owner, user=user)
    properties = Property.objects.filter(owner_id=user_id)
    leases = Lease.objects.filter(property__owner=owner)
    revenue = leases.aggregate(Sum('rent_amount'))['rent_amount__sum']
    contracts_made = leases.filter(contract_accepted=False)
    contracts_accepted = leases.filter(contract_accepted=True)
    contracts_signed = leases.filter(contract_signed=True)
    tenant = Tenant.objects.filter(leases__in=leases)
    tenants = tenant.count()

    context = {
        'user': user,
        'owner': owner,
        'properties': properties,
        'contracts_made': contracts_made,
        'contracts_accepted': contracts_accepted,
        'contracts_signed': contracts_signed,
        'leases': leases,
        'revenue': revenue,
        'tenants': tenants
    }
    return render(request, 'Others_dashboard/owners/owner_dashboard.html', context)


@csrf_exempt
def owner_profile(request, user_id):
    user = get_object_or_404(User, id=user_id)
    owner = get_object_or_404(Owner, user=user)
    return render(request, 'Others_dashboard/owners/owner_profile/owner_profile.html', {'user': user, 'owner': owner})


@csrf_exempt
def edit_owner_profile(request, id):
    owner = get_object_or_404(Owner, id=id)
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        address = request.POST.get('address')
        user_id = request.POST.get('user_id')
        image = request.FILES.get('image')
        if image:
            owner.image = image
        owner.name = name
        owner.email = email
        owner.phone = phone
        owner.user = user_id
        owner.address = address
        owner.save()
        messages.success(request, 'Owner details updated successfully.')
        return redirect('owner_profile', owner.user.id)
    return render(request, 'Others_dashboard/owners/owner_profile/owner_profile.html', {'owner': owner})


@csrf_exempt
def view_profile(request, user_id):
    user = get_object_or_404(User, id=user_id)
    owner = get_object_or_404(Owner, user=user)
    return render(request, 'Others_dashboard/owners/owner_profile/view_details.html', {'user': user, 'owner': owner})


@csrf_exempt
def create_owner_profile(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone_number')
        address = request.POST.get('address')
        image = request.FILES.get('image')
        user_id = user.id
        owner = Owner.objects.create(name=name, email=email, phone_number=phone_number, address=address, image=image, user_id=user_id)
        owner.save()
        messages.success(request, 'Owner profile created successfully.')
        return redirect('owner_profile', owner.user.id)
    return render(request, 'Others_dashboard/owners/owner_profile/create_profile.html', {'user': user})


@csrf_exempt
def owner_properties(request, user_id):
    user = get_object_or_404(User, id=user_id)
    owner = get_object_or_404(Owner, user=user)
    properties = Property.objects.filter(owner=owner)
    return render(request, 'Others_dashboard/owners/owner_properties/owner_properties.html', {'user': user, 'owner': owner, 'properties': properties})


@csrf_exempt
def owner_add_property(request, user_id):
    user = get_object_or_404(User, id=user_id)
    owner = get_object_or_404(Owner, user=user)
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            address = request.POST.get('address')
            types = request.POST.get('property_type')
            description = request.POST.get('description')
            number_of_units = request.POST.get('number_of_units')
            price = request.POST.get('price')
            image = request.FILES.get('image')
            owner_id = request.POST.get('owner')

            property_instance = Property.objects.create(
                name=name,
                address=address,
                types=types,
                description=description,
                price=price,
                image=image,
                number_of_units=number_of_units,
                owner_id=owner_id,
            )

            unit_numbers = request.POST.getlist('unit_number[]')
            bedrooms = request.POST.getlist('bedrooms[]')
            bathrooms = request.POST.getlist('bathrooms[]')
            rents = request.POST.getlist('rent[]')
            availabilities = request.POST.getlist('is_available[]')

            if not (len(unit_numbers) == len(bedrooms) == len(bathrooms) == len(rents)):
                messages.error(request, 'Mismatched number of unit details submitted.')
                return redirect('owner_add_property', owner.user.id)

            for i in range(len(unit_numbers)):
                Unit.objects.create(
                    property=property_instance,
                    unit_number=unit_numbers[i],
                    bedrooms=bedrooms[i],
                    bathrooms=bathrooms[i],
                    rent=rents[i],
                    is_available=availabilities[i] == 'on' if availabilities[i] else False
                )

            messages.success(request, 'Property added successfully')
            return redirect('owner_properties', owner.user.id)
        except Exception as e:
            messages.error(request, f'Error adding property: {e}')
            return redirect('owner_add_property')

    return render(request, 'Others_dashboard/owners/owner_properties/owner_addproperty.html', {'user': user, 'owner': owner})


@csrf_exempt
def owner_contracts(request, user_id):
    user = get_object_or_404(User, id=user_id)
    owner = get_object_or_404(Owner, user=user)
    properties = Property.objects.filter(owner=owner)
    leases = Lease.objects.filter(property__owner=owner)
    made_leases = leases.filter(contract_accepted=False)
    accepted_leases = leases.filter(contract_accepted=True)
    signed_leases = leases.filter(contract_signed=True)
    context = {
        'user': user,
        'owner': owner,
        'properties': properties,
        'made_leases': made_leases,
        'accepted_leases': accepted_leases,
        'signed_leases': signed_leases,
        'leases': leases
    }
    return render(request, 'Others_dashboard/owners/leases/owner_contracts.html', context)


@csrf_exempt
def new_contract(request, user_id):
    user = get_object_or_404(User, id=user_id)
    owner = get_object_or_404(Owner, user=user)
    properties = Property.objects.filter(owner=owner)
    tenants = Tenant.objects.all()
    if request.method == 'POST':
        try:
            property_id = request.POST.get('property')
            tenant_id = request.POST.get('tenant')
            start_date = request.POST.get('start_date')
            end_date = request.POST.get('end_date')
            rent_amount = request.POST.get('rent_amount')
            contract_details = request.POST.get('contract_details')
            Lease.objects.create(
                property_id=property_id,
                tenant_id=tenant_id,
                start_date=start_date,
                end_date=end_date,
                rent_amount=rent_amount,
                contract_details=contract_details,
            )

            return redirect('owner_contracts', owner.user.id)
        except Exception as e:
            messages.error(request, f'Error creating contract: {e}')
            return redirect('new_contract', owner.user.id)

    return render(request, 'Others_dashboard/owners/leases/new_contract.html', {'user': user, 'owner': owner, 'properties': properties, 'tenants': tenants})


@csrf_exempt
def owner_view_contract(request, lease_id):
    user = request.user
    owner = get_object_or_404(Owner, user=user)
    lease = get_object_or_404(Lease, id=lease_id)
    return render(request, 'Others_dashboard/owners/leases/view_contract.html', {'user': user, 'owner': owner, 'lease': lease})


@csrf_exempt
def download_contract(request, lease_id):
    lease = get_object_or_404(Lease, id=lease_id)

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{lease.property.name}_contract.pdf"'

    p = canvas.Canvas(response, pagesize=letter)
    width, height = letter

    p.setFont("Helvetica-Bold", 16)
    p.drawString(1 * inch, height - 1 * inch, "Contract Details")

    p.setFont("Helvetica", 12)
    y = height - 1.5 * inch
    p.drawString(1 * inch, y, f"Property: {lease.property.name}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Tenant: {lease.tenant.name}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Owner: {lease.property.owner.name}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Start Date: {lease.start_date}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"End Date: {lease.end_date}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Rent Amount: {lease.rent_amount} Frw")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Property Type: {lease.property.get_types_display()}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Address: {lease.property.address}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Number of Units: {lease.property.number_of_units}")
    y -= 0.5 * inch

    p.setFont("Helvetica-Bold", 12)
    p.drawString(1 * inch, y, "Status:")
    p.setFont("Helvetica", 12)
    p.drawString(2 * inch, y, f"{lease.get_status_display()}")
    y -= 0.5 * inch

    p.setFont("Helvetica-Bold", 12)
    p.drawString(1 * inch, y, "Contract Details:")
    p.setFont("Helvetica", 12)
    y -= 0.5 * inch

    contract_details_lines = lease.contract_details.split('\n')
    for line in contract_details_lines:
        p.drawString(1 * inch, y, line)
        y -= 0.5 * inch
        if y < 1 * inch:
            p.showPage()
            y = height - 1.5 * inch

    p.showPage()
    p.save()

    return response


@csrf_exempt
def delete_contract(request, lease_id):
    lease = get_object_or_404(Lease, id=lease_id)
    lease.delete()
    return redirect('owner_contracts', lease.property.owner.user.id)


@csrf_exempt
def owner_edit_property(request, property_id):
    property_instance = get_object_or_404(Property, id=property_id)
    owner = property_instance.owner
    user = owner.user

    if request.method == 'POST':
        try:
            property_instance.name = request.POST.get('name')
            property_instance.address = request.POST.get('address')
            property_instance.types = request.POST.get('property_type')
            property_instance.description = request.POST.get('description')
            property_instance.number_of_units = request.POST.get('number_of_units')
            property_instance.price = request.POST.get('price')

            if 'image' in request.FILES:
                property_instance.image = request.FILES.get('image')

            property_instance.save()

            unit_numbers = request.POST.getlist('unit_number[]')
            bedrooms = request.POST.getlist('bedrooms[]')
            bathrooms = request.POST.getlist('bathrooms[]')
            rents = request.POST.getlist('rent[]')
            availabilities = request.POST.getlist('is_available[]')

            if not (len(unit_numbers) == len(bedrooms) == len(bathrooms) == len(rents)):
                messages.error(request, 'Mismatched number of unit details submitted.')
                return redirect('owner_edit_property', property_instance.id)

            existing_units = list(property_instance.units.all())

            for i in range(len(unit_numbers)):
                if i < len(existing_units):
                    unit = existing_units[i]
                    unit.unit_number = unit_numbers[i]
                    unit.bedrooms = bedrooms[i]
                    unit.bathrooms = bathrooms[i]
                    unit.rent = rents[i]
                    unit.is_available = availabilities[i] == 'on' if availabilities[i] else False
                    unit.save()
                else:
                    Unit.objects.create(
                        property=property_instance,
                        unit_number=unit_numbers[i],
                        bedrooms=bedrooms[i],
                        bathrooms=bathrooms[i],
                        rent=rents[i],
                        is_available=availabilities[i] == 'on' if availabilities[i] else False
                    )

            messages.success(request, 'Property updated successfully')
            return redirect('owner_properties', owner.user.id)
        except Exception as e:
            messages.error(request, f'Error updating property: {e}')
            return redirect('owner_edit_property', property_instance.id)

    units = property_instance.units.all()
    unit_data = []
    for unit in units:
        unit_data.append({
            'unit_number': unit.unit_number,
            'bedrooms': unit.bedrooms,
            'bathrooms': unit.bathrooms,
            'rent': unit.rent,
            'is_available': unit.is_available
        })

    return render(request, 'Others_dashboard/owners/owner_properties/owner_editproperty.html', {
        'user': user,
        'owner': owner,
        'property_instance': property_instance,
        'units': units,
        'unit_data': unit_data
    })


@csrf_exempt
def owner_delete_property(request, property_id):
    property_instance = get_object_or_404(Property, id=property_id)
    property_instance.delete()
    return redirect('owner_properties', property_instance.owner.user.id)


@csrf_exempt
def owner_view_property(request, property_id):
    user = request.user
    units = Unit.objects.filter(property_id=property_id)
    owner = get_object_or_404(Owner, user=user)
    property_instance = get_object_or_404(Property, id=property_id)
    return render(request, 'Others_dashboard/owners/owner_properties/view_properties.html', {'user': user, 'owner': owner, 'property_instance': property_instance, 'units': units})


@csrf_exempt

@login_required
def tenant_dashboard(request, user_id):
    user = get_object_or_404(User, id=user_id)
    tenant = get_object_or_404(Tenant, user=user)
    properties = Property.objects.filter(leases__tenant__user_id__in=[user_id])
    leases = Lease.objects.filter(tenant=tenant)
    made_leases = leases.filter(contract_accepted=False)
    accepted_leases = leases.filter(contract_accepted=True)
    signed_leases = leases.filter(contract_signed=True)
    context = {
        'user': user,
        'tenant': tenant,
        'properties': properties,
        'made_leases': made_leases,
        'accepted_leases': accepted_leases,
        'signed_leases': signed_leases,
        'leases': leases
    }
    return render(request, 'Others_dashboard/Tenants/tenant_dashboard.html', context)


@csrf_exempt
@login_required
def new_tenant(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        form = TenantProfileForm(request.POST, request.FILES)
        if form.is_valid():
            tenant = form.save(commit=False)
            tenant.user = user
            tenant.save()
            return redirect('tenant_dashboard', user.id)
    else:
        form = TenantProfileForm()

    return render(request, 'Others_dashboard/Tenants/profile/new_tenant.html', {'form': form})

@csrf_exempt
@login_required
def like_property(request, property_id):
    property = get_object_or_404(Property, id=property_id)
    liked_property, created = LikedProperties.objects.get_or_create(user=request.user, property=property)
    if created:
        liked_property.total_likes += 1
        liked_property.save()
        messages.success(request, "You have liked this property!")
        return redirect('property_view', property.id)
    else:
        messages.info(request, "You have already liked this property!")
    return redirect('property_view', property.id)

@csrf_exempt
@login_required
def schedule_visit(request, property_id):
    property = get_object_or_404(Property, id=property_id)
    tenant = get_object_or_404(Tenant, user=request.user)
    if request.method == 'POST':
        visit_date = request.POST.get('visit_date')
        description = request.POST.get('description')
        Visit.objects.create(property=property, tenant=tenant, visit_date=visit_date, description=description)
        messages.success(request, "Your visit has been scheduled!")
        return redirect('property_view', property.id)

    return render(request, 'home/details.html', {'property': property})


@csrf_exempt
def tenant_profile(request,user_id):
    tenant = get_object_or_404(Tenant, user_id=user_id)
    user = get_object_or_404(User, id=user_id)
    context = {'user': user, 'tenant': tenant}
    return render(request, 'Others_dashboard/Tenants/profile/Tenant_profile.html', context)

@csrf_exempt
def tenant_edit_profile(request, user_id):
    user = get_object_or_404(User, id=user_id)
    tenant = get_object_or_404(Tenant, user=user)
    if request.method == 'POST':
        form = TenantProfileForm(request.POST, request.FILES, instance=tenant)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully')
            return redirect('tenant_profile', user.id)
    else:
        form = TenantProfileForm(instance=tenant)
        return render(request, 'Others_dashboard/Tenants/profile/tenant_edit_profile.html', {'form': form, 'user': user})

@csrf_exempt
def tenant_properties(request, user_id):
    user = get_object_or_404(User, id=user_id)
    tenant = get_object_or_404(Tenant, user=user)

    # Filter leases by the tenant and signed is true
    leases = Lease.objects.filter(tenant=tenant , contract_signed=True)

    # Initialize properties list
    properties = [lease.property for lease in leases]

    # Apply search filters
    search_query = request.GET.get('search', '')
    type_filter = request.GET.get('type', '')
    owner_filter = request.GET.get('owner', '')

    if search_query:
        properties = [p for p in properties if
                      search_query.lower() in p.address.lower() or str(search_query) in str(p.price)]

    if type_filter:
        properties = [p for p in properties if p.types == type_filter]

    if owner_filter:
        properties = [p for p in properties if p.owner.id == int(owner_filter)]

    # Pagination
    paginator = Paginator(properties, 10)  # Show 10 properties per page
    page_number = request.GET.get('page')
    properties = paginator.get_page(page_number)

    # Prepare context
    context = {
        'user': user,
        'tenant': tenant,
        'properties': properties,
        'type_list': Property.objects.values_list('types', flat=True).distinct(),
        'owner_list': Property.objects.values_list('owner', flat=True).distinct()
    }

    return render(request, 'Others_dashboard/Tenants/owner_properties/tenant_properties.html', context)

@csrf_exempt
def tenant_contracts(request, user_id):
    user = get_object_or_404(User, id=user_id)
    tenant = get_object_or_404(Tenant, user=user)
    leases = Lease.objects.filter(tenant=tenant)
    signed_contracts = [lease for lease in leases if lease.contract_signed ]
    unaccepted_contracts = [lease for lease in leases if not lease.contract_accepted and not lease.contract_signed]
    accepted_contracts = [lease for lease in leases if lease.contract_accepted and not lease.contract_signed]
    total_signed_contracts = len(signed_contracts)
    total_accepted_contracts = len(accepted_contracts)
    total_unaccepted_contracts = len(unaccepted_contracts)

    context = {
        'user': user,
        'tenant': tenant,
        'signed_contracts': signed_contracts,
        'accepted_contracts': accepted_contracts,
        'unaccepted_contracts': unaccepted_contracts,
        'total_signed_contracts': total_signed_contracts,
        'total_accepted_contracts': total_accepted_contracts,
        'total_unaccepted_contracts': total_unaccepted_contracts
    }
    return render(request, 'Others_dashboard/Tenants/contracts/tenant_contracts.html', context)
@csrf_exempt
def tenant_accept_contract(request, lease_id):
    lease = get_object_or_404(Lease, id=lease_id)
    lease.contract_accepted = True
    lease.save()
    messages.success(request, "Contract accepted successfully!")
    return redirect('tenant_contracts', lease.tenant.user.id)
@csrf_exempt
def tenant_sign_contract(request, lease_id):
    lease = get_object_or_404(Lease, id=lease_id)
    lease.contract_signed = True
    lease.save()
    messages.success(request, "Contract signed successfully!")
    return redirect('tenant_contracts', lease.tenant.user.id)

@csrf_exempt
def tenant_view_contract(request, lease_id):
    lease = get_object_or_404(Lease, id=lease_id)
    return render(request, 'Others_dashboard/Tenants/contracts/view_contract.html', {'lease': lease})

@csrf_exempt
def tenant_download_contract(request, lease_id):
    lease = get_object_or_404(Lease, id=lease_id)

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{lease.property.name}_contract.pdf"'

    p = canvas.Canvas(response, pagesize=letter)
    width, height = letter

    p.setFont("Helvetica-Bold", 16)
    p.drawString(1 * inch, height - 1 * inch, "Contract Details")

    p.setFont("Helvetica", 12)
    y = height - 1.5 * inch
    p.drawString(1 * inch, y, f"Property: {lease.property.name}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Tenant: {lease.tenant.name}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Owner: {lease.property.owner.name}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Start Date: {lease.start_date}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"End Date: {lease.end_date}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Rent Amount: {lease.rent_amount} Frw")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Property Type: {lease.property.get_types_display()}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Address: {lease.property.address}")
    y -= 0.5 * inch
    p.drawString(1 * inch, y, f"Number of Units: {lease.property.number_of_units}")
    y -= 0.5 * inch

    p.setFont("Helvetica-Bold", 12)
    p.drawString(1 * inch, y, "Status:")
    p.setFont("Helvetica", 12)
    p.drawString(2 * inch, y, f"{lease.get_status_display()}")
    y -= 0.5 * inch

    p.setFont("Helvetica-Bold", 12)
    p.drawString(1 * inch, y, "Contract Details:")
    p.setFont("Helvetica", 12)
    y -= 0.5 * inch

    contract_details_lines = lease.contract_details.split('\n')
    for line in contract_details_lines:
        p.drawString(1 * inch, y, line)
        y -= 0.5 * inch
        if y < 1 * inch:
            p.showPage()
            y = height - 1.5 * inch

    p.showPage()
    p.save()

    return response

@csrf_exempt
def tenant_view_property(request, property_id):
    property_instance = get_object_or_404(Property, id=property_id)
    units = property_instance.units.all()
    tenant = get_object_or_404(Tenant, user=request.user)
    leases = Lease.objects.filter(property=property_instance, tenant=tenant)

    context = {
        'property_instance': property_instance,
        'units': units,
        'leases': leases,
    }
    return render(request, 'Others_dashboard/Tenants/owner_properties/view_property.html', context)


paypalrestsdk.configure({
    "mode": settings.PAYPAL_MODE,  # sandbox or live
    "client_id": settings.PAYPAL_CLIENT_ID,
    "client_secret": settings.PAYPAL_CLIENT_SECRET
})

@csrf_exempt
def process_payment(request):
    if request.method == 'POST':
        property_id = request.POST.get('property')
        amount = request.POST.get('amount')
        date_paid = request.POST.get('date_paid')

        property_instance = get_object_or_404(Property, id=property_id)
        tenant = get_object_or_404(Tenant, user=request.user)

        # Create a payment object
        payment = paypalrestsdk.Payment({
            "intent": "sale",
            "payer": {
                "payment_method": "paypal"
            },
            "transactions": [{
                "amount": {
                    "total": amount,
                    "currency": "USD"  # Change currency as needed
                },
                "description": f"Payment for property {property_instance.name}"
            }],
            "redirect_urls": {
                "return_url": f"{settings.SITE_URL}/payment/execute/",
                "cancel_url": f"{settings.SITE_URL}/payment/cancel/"
            }
        })

        if payment.create():
            for link in payment.links:
                if link.rel == "approval_url":
                    return redirect(link.href)
        else:
            messages.error(request, 'Error creating payment on PayPal.')
            return redirect('make_payment')
    else:
        tenant = get_object_or_404(Tenant, user=request.user)
        leases = Lease.objects.filter(tenant=tenant)

        context = {
            'leases': leases,
        }
        return render(request, 'Others_dashboard/Tenants/payments/tenant_payment.html', context)

@csrf_exempt
def execute_payment(request):
    payment_id = request.GET.get('paymentId')
    payer_id = request.GET.get('PayerID')

    payment = paypalrestsdk.Payment.find(payment_id)

    if payment.execute({"payer_id": payer_id}):
        # Save the payment to the database
        property_id = payment.transactions[0].description.split()[-1]
        property_instance = get_object_or_404(Property, id=property_id)
        tenant = get_object_or_404(Tenant, user=request.user)

        Payment.objects.create(
            property=property_instance,
            tenant=tenant,
            amount=payment.transactions[0].amount.total,
            date_paid=payment.transactions[0].related_resources[0].sale.create_time
        )

        messages.success(request, 'Payment successful.')
        return redirect('tenant_lease_management')
    else:
        messages.error(request, 'Error executing payment on PayPal.')
        return redirect('make_payment')