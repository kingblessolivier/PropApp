from rest_framework import serializers
from .models import Tenant, Property, Lease, Unit


class PropertySerializer(serializers.ModelSerializer):
    class Meta:
        model = Property
        fields = ['id', 'name', 'address', 'types', 'description', 'number_of_units']
        extra_kwargs = {
            'number_of_units': {'required': False},
            'id': {'read_only': True}

        }


class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = '__all__'


class LeaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lease
        fields = ['id', 'unit', 'tenant', 'start_date', 'end_date', 'rent_amount']
        extra_kwargs = {
            'id': {'read_only': True}
        }

        def create(self, validated_data):
            unit_data = validated_data.pop('unit')
            unit_instance = Unit.objects.get(id=unit_data['id'])
            tenant_data = validated_data.pop('tenant')
            tenant_instance = Tenant.objects.get(id=tenant_data['id'])
            lease_instance = Lease.objects.create(unit=unit_instance, tenant=tenant_instance, **validated_data)
            return lease_instance


class UnitSerializer(serializers.ModelSerializer):
    class Meta:
        model = Unit
        fields = ['id', 'property', 'unit_number', 'bedrooms', 'bathrooms', 'rent', 'is_available']

        def create(self, validated_data):
            property_data = validated_data.pop('property')
            property_instance = Property.objects.get(id=property_data['id'])
            unit_instance = Unit.objects.create(property=property_instance, **validated_data)
            return unit_instance
