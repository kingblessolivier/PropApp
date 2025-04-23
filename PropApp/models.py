from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.timezone import now

user_roles = (
    ('Owner', 'Owner'),
    ('Tenant', 'Tenant'),
    ('Admin', 'Admin'),
)

property_status = (
    ('Available', 'Available'),
    ('Rented', 'Rented'),
)

property_type = (
    ('Apartment', 'Apartment'),
    ('House', 'House'),
    ('Commercial', 'Commercial'),
)

class User(AbstractUser):
    role = models.CharField(max_length=10, choices=user_roles, default='Tenant')

    def __str__(self):
        return self.username

class Owner(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    phone_number = models.CharField(max_length=15)
    address = models.CharField(max_length=200)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='owner_profile')
    image = models.ImageField(upload_to='owner_images', blank=True)

    def __str__(self):
        return self.name

class Property(models.Model):
    name = models.CharField(max_length=100)
    address = models.CharField(max_length=200)
    types = models.CharField(max_length=10, choices=property_type)
    description = models.TextField()
    image = models.ImageField(upload_to='property_images', blank=True)
    number_of_units = models.IntegerField()
    status = models.CharField(max_length=20, choices=property_status, default='Available')
    price = models.IntegerField()
    owner = models.ForeignKey(Owner, on_delete=models.CASCADE, related_name='properties')
    date_added = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} at {self.address}"

class Unit(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='units')
    unit_number = models.IntegerField()
    bedrooms = models.IntegerField()
    bathrooms = models.IntegerField()
    rent = models.IntegerField()
    is_available = models.BooleanField(default=True)

    def __str__(self):
        return f"Unit {self.unit_number} in {self.property.name}"

class Tenant(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    phone_number = models.CharField(max_length=15)
    address = models.CharField(max_length=200)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='tenant_profile')
    image = models.ImageField(upload_to='tenant_images', blank=True)

    def __str__(self):
        return self.name

class Lease(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='leases', null=True)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='leases')
    contract_details = models.TextField(blank=True, null=True)
    start_date = models.DateField()
    end_date = models.DateField()
    contract_accepted = models.BooleanField(default=False)
    contract_signed = models.BooleanField(default=False)
    contract_archived = models.BooleanField(default=False)
    rent_amount = models.IntegerField()

    class Meta:
        verbose_name_plural = "Leases"

    def get_status_display(self):
        if self.contract_accepted and self.contract_signed:
            return "Signed"
        elif self.contract_accepted:
            return "Accepted"
        else:
            return "Made"

class CustomerMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_archived = models.BooleanField(default=False)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"Message from {self.name} ({self.email})"

class Updates(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    end_date = models.DateField()

    class Meta:
        verbose_name_plural = "Updates"

    def __str__(self):
        return self.title

class Email(models.Model):
    sender_email = models.EmailField(max_length=255, verbose_name="Sender's Email")
    recipient_email = models.EmailField(max_length=255, verbose_name="Recipient's Email")
    subject = models.CharField(max_length=255, verbose_name="Email Subject")
    body = models.TextField(verbose_name="Email Body")
    timestamp = models.DateTimeField(default=now, verbose_name="Received At")
    is_read = models.BooleanField(default=False, verbose_name="Read Status")

    def __str__(self):
        return f"Email from {self.sender_email} to {self.recipient_email}"

    class Meta:
        verbose_name_plural = "Emails"

class CustRequest(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='cust_requests')
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_archived = models.BooleanField(default=False)
    is_read = models.BooleanField(default=False)

class MaintenanceRequest(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='maint_requests')
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='maint_requests')
    title = models.CharField(max_length=100)
    description = models.TextField()
    request_date = models.DateTimeField(auto_now_add=True)
    completion_date = models.DateTimeField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=[
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed')
    ], default='open')

    def __str__(self):
        return f"{self.tenant.user.username} - {self.request_date}"
class Payment(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='payments')
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='payments')
    amount = models.IntegerField()
    date_paid = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f"{self.tenant.user.username} - {self.date_paid}"
class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    content = models.TextField()
    sent_date = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"From {self.sender.username} to {self.recipient.username} - {self.sent_date}"
class Visit(models.Model):
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='visits')
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name='visits')
    visit_date = models.DateTimeField(auto_now_add=True)
    description = models.TextField()
    def __str__(self):
        return f"{self.tenant.user.username} - {self.visit_date}"
class LikedProperties(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='liked_properties')
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='liked_by')
    total_likes = models.IntegerField(default=0)
    def __str__(self):
        return f"{self.user.username} - {self.property.name} - {self.total_likes} "









