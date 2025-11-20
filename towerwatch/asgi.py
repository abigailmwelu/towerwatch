import os
from channels.routing import ProtocolTypeRouter
from django.core.asgi import get_asgi_application
from channels.auth import AuthMiddlewareStack

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "towerwatch.settings")

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
})
