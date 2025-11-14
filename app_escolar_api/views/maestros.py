from django.db.models import *
from django.db import transaction
from app_escolar_api.serializers import UserSerializer
from app_escolar_api.serializers import *
from app_escolar_api.models import *
from rest_framework import permissions
from rest_framework import generics
from rest_framework import status
from rest_framework.response import Response
from django.contrib.auth.models import Group
import json
from django.shortcuts import get_object_or_404

class MaestrosAll(generics.CreateAPIView):
    # Obtener la lista de todos los maestros activos
    # Necesita permisos de autenticación de usuario para poder acceder a la petición
    permission_classes = (permissions.IsAuthenticated,)
    def get(self, request, *args, **kwargs):
        maestros = Maestros.objects.filter(user__is_active=1).order_by("id")
        lista = MaestroSerializer(maestros, many=True).data
        for maestro in lista:
            if isinstance(maestro, dict) and "materias_json" in maestro:
                try:
                    maestro["materias_json"] = json.loads(maestro["materias_json"])
                except Exception:
                    maestro["materias_json"] = []
        return Response(lista, 200)
    
class MaestrosView(generics.CreateAPIView):
    #Registrar nuevo usuario maestro
    @transaction.atomic
    def post(self, request, *args, **kwargs):
        user = UserSerializer(data=request.data)
        if user.is_valid():
            role = request.data['rol']
            first_name = request.data['first_name']
            last_name = request.data['last_name']
            email = request.data['email']
            password = request.data['password']
            existing_user = User.objects.filter(email=email).first()
            if existing_user:
                return Response({"message":"Username "+email+", is already taken"},400)
            user = User.objects.create( username = email,
                                        email = email,
                                        first_name = first_name,
                                        last_name = last_name,
                                        is_active = 1)
            user.save()
            user.set_password(password)
            user.save()
            
            group, created = Group.objects.get_or_create(name=role)
            group.user_set.add(user)
            user.save()
            #Create a profile for the user
            maestro = Maestros.objects.create(user=user,
                                            id_trabajador= request.data["id_trabajador"],
                                            fecha_nacimiento= request.data["fecha_nacimiento"],
                                            telefono= request.data["telefono"],
                                            rfc= request.data["rfc"].upper(),
                                            cubiculo= request.data["cubiculo"],
                                            area_investigacion= request.data["area_investigacion"],
                                            materias_json = json.dumps(request.data["materias_json"]))
            maestro.save()
            return Response({"maestro_created_id": maestro.id }, 201)
        return Response(user.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # Actualizar datos del maestro
    # TODO: Agregar actualización de maestros
    
    # Eliminar maestro con delete (Borrar realmente)
    @transaction.atomic
    def delete(self, request, *args, **kwargs):
        maestro = get_object_or_404(Maestros, id=request.GET.get("id"))
        try:
            maestro.user.delete()
            return Response({"details":"Maestro eliminado"},200)
        except Exception as e:
            return Response({"details":"Algo pasó al eliminar"},400)