from .models import AuditLog


def get_client_ip(request):
    if not request:
        return None

    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR")


def log_action(user, action, object_type, object_id, detail=None, request=None):
    AuditLog.objects.create(
        user=user,
        action=action,
        object_type=object_type,
        object_id=object_id,
        detail=detail or {},
        ip_address=get_client_ip(request),
    )