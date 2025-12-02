from django.db import transaction
from django.shortcuts import get_object_or_404

from app_escolar_api.serializers import MateriaSerializer
from app_escolar_api.models import Materias
from rest_framework import permissions, generics, status
from rest_framework.response import Response


class MateriasAll(generics.CreateAPIView):
    # Verificar si el usuario esta autenticado
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = MateriaSerializer

    def get(self, request, *args, **kwargs):
        # List all materias
        materia = Materias.objects.all().order_by("id")
        lista = MateriaSerializer(materia, many=True).data
        return Response(lista, status=status.HTTP_200_OK)


class MateriasView(generics.CreateAPIView):
    # Permisos por método (sobrescribe el comportamiento default)
    # Verifica que el usuario esté autenticado para las peticiones GET, PUT y DELETE
    def get_permissions(self):
        if self.request.method in ['GET', 'PUT', 'DELETE']:
            return [permissions.IsAuthenticated()]
        return []  # POST no requiere autenticación

    # Obtener materia por ID
    def get(self, request, *args, **kwargs):
        materia = get_object_or_404(Materias, id=request.GET.get("id"))
        materia = MateriaSerializer(materia, many=False).data
        return Response(materia, status=status.HTTP_200_OK)

    # Registrar nueva materia
    @transaction.atomic
    def post(self, request, *args, **kwargs):
        materia_serializer = MateriaSerializer(data=request.data)
        if materia_serializer.is_valid():
            materia = materia_serializer.save()
            return Response({"Materia creada con ID": materia.id}, status=status.HTTP_201_CREATED)
        print(materia_serializer.errors)
        return Response(materia_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Actualizar datos de la materia
    @transaction.atomic
    def put(self, request, *args, **kwargs):
        # Verifica que el usuario esté autenticado (handled by get_permissions)
        materia = get_object_or_404(Materias, id=request.data.get("id"))
        serializer = MateriaSerializer(materia, data=request.data, partial=True)
        if serializer.is_valid():
            materia = serializer.save()
            return Response({"message": "Materia actualizada correctamente", "materia": serializer.data},
                            status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Eliminar materia
    @transaction.atomic
    def delete(self, request, *args, **kwargs):
        materia = get_object_or_404(Materias, id=request.GET.get("id"))
        try:
            materia.delete()
            return Response({"details": "Materia eliminada"}, status=status.HTTP_200_OK)
        except Exception:
            return Response({"details": "Algo pasó al eliminar"}, status=status.HTTP_400_BAD_REQUEST)