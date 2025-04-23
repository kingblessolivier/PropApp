from django.contrib import admin
from .models import (
    Property, Unit, Tenant, Lease, User,
    CustomerMessage, Owner, Updates, Email,
    CustRequest, MaintenanceRequest, Payment, Message, Visit,LikedProperties
)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_staff', 'is_active', 'role')
    list_filter = ('is_staff', 'is_active', 'role')
    search_fields = ('username', 'email')


@admin.register(Owner)
class OwnerAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'phone_number', 'address', 'image')
    search_fields = ('name',)


@admin.register(Property)
class PropertyAdmin(admin.ModelAdmin):
    list_display = ('name', 'address', 'types', 'description', 'image', 'number_of_units')
    list_filter = ('types',)
    search_fields = ('name',)


@admin.register(Unit)
class UnitAdmin(admin.ModelAdmin):
    list_display = ('unit_number', 'rent', 'bathrooms', 'bedrooms', 'is_available')
    list_filter = ('is_available',)
    search_fields = ('unit_number',)


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'phone_number', 'address', 'image')
    search_fields = ('name',)


@admin.register(Lease)
class LeaseAdmin(admin.ModelAdmin):
    list_display = ('tenant', 'property', 'start_date', 'end_date')
    list_filter = ('start_date',)
    search_fields = ('tenant__name',)


@admin.register(CustomerMessage)
class CustomerMessageAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'message', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('name', 'email')


@admin.register(Updates)
class UpdatesAdmin(admin.ModelAdmin):
    list_display = ('title', 'description', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('title',)


@admin.register(Email)
class EmailAdmin(admin.ModelAdmin):
    list_display = ('sender_email', 'subject')


@admin.register(CustRequest)
class CustRequestAdmin(admin.ModelAdmin):
    list_display = ('property', 'name', 'email', 'created_at', 'is_archived', 'is_read')
    list_filter = ('created_at', 'is_archived', 'is_read')
    search_fields = ('property__name', 'name', 'email')


@admin.register(MaintenanceRequest)
class MaintenanceRequestAdmin(admin.ModelAdmin):
    list_display = ('property', 'tenant', 'title', 'request_date', 'status')
    list_filter = ('status', 'request_date')
    search_fields = ('title', 'tenant__user__username')


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('property', 'tenant', 'amount', 'date_paid')
    list_filter = ('date_paid',)
    search_fields = ('tenant__user__username',)


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'recipient', 'sent_date', 'is_read')
    list_filter = ('sent_date', 'is_read')
    search_fields = ('sender__username', 'recipient__username')


@admin.register(Visit)
class VisitAdmin(admin.ModelAdmin):
    list_display = ('property', 'tenant', 'visit_date')
    list_filter = ('visit_date',)
    search_fields = ('tenant__user__username',)
@admin.register(LikedProperties)
class LikedPropertiesAdmin(admin.ModelAdmin):
    list_display = ('user', 'property')
    search_fields = ('user__username', 'property__name')