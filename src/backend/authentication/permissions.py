"""
Custom Permissions for SecureSys Auditor.

Centralized permission classes following Single Responsibility Principle.
"""
from rest_framework import permissions


class IsAdminRole(permissions.BasePermission):
    """
    Allow access only to users with admin role.
    """
    
    message = "Admin role required for this action."
    
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated and
            getattr(request.user, 'role', None) == 'admin'
        )


class IsAuditorOrAdmin(permissions.BasePermission):
    """
    Allow access to users with auditor or admin role.
    """
    
    message = "Auditor or admin role required for this action."
    
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        return getattr(request.user, 'role', None) in ['auditor', 'admin']


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Allow read access to all authenticated users.
    Write access only to admins.
    """
    
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        return (
            request.user.is_authenticated and
            getattr(request.user, 'role', None) == 'admin'
        )


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Object-level permission.
    Allow access to object owner or admin.
    """
    
    def has_object_permission(self, request, view, obj):
        if getattr(request.user, 'role', None) == 'admin':
            return True
        
        # Check if object has owner field
        owner_field = getattr(view, 'owner_field', 'user')
        owner = getattr(obj, owner_field, None)
        
        if owner is None:
            return False
        
        return owner == request.user


class CanAccessSystem(permissions.BasePermission):
    """
    Permission to access system-related resources.
    
    For multi-tenant deployments, checks if user
    has access to the system.
    """
    
    def has_permission(self, request, view):
        return request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        # Admin can access everything
        if getattr(request.user, 'role', None) == 'admin':
            return True
        
        # Get system from object
        system = getattr(obj, 'system', obj)
        
        # Check if user has access to this system
        # This can be extended for multi-tenant support
        if hasattr(system, 'owners'):
            return system.owners.filter(id=request.user.id).exists()
        
        # Default: allow access for authenticated users
        return True
