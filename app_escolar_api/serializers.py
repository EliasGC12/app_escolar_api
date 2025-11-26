from django.contrib.auth.models import User
from rest_framework import serializers
from .models import *
import json

class UserSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ('id','first_name','last_name', 'email')

class AdminSerializer(serializers.ModelSerializer):
    user=UserSerializer(read_only=True)
    class Meta:
        model = Administradores
        fields = '__all__'
        
class AlumnoSerializer(serializers.ModelSerializer):
    user=UserSerializer(read_only=True)
    class Meta:
        model = Alumnos
        fields = "__all__"

class MaestroSerializer(serializers.ModelSerializer):
    user=UserSerializer(read_only=True)
    class Meta:
        model = Maestros
        fields = '__all__'

class MateriaSerializer(serializers.ModelSerializer):
    dias = serializers.ListField(child=serializers.CharField(), allow_empty=True, required=False)

    class Meta:
        model = Materias
        fields = "__all__"

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        dias = instance.dias
        if dias is None or dias == "":
            ret['dias'] = []
        else:
            try:
                ret['dias'] = json.loads(dias)
            except (TypeError, ValueError):
                # if stored value isn't JSON, try to return it as a list or single value
                ret['dias'] = dias if isinstance(dias, list) else [dias]
        return ret

    def create(self, validated_data):
        dias = validated_data.get('dias', None)
        if isinstance(dias, (list, dict)):
            validated_data['dias'] = json.dumps(dias)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        dias = validated_data.get('dias', None)
        if isinstance(dias, (list, dict)):
            validated_data['dias'] = json.dumps(dias)
        return super().update(instance, validated_data)
