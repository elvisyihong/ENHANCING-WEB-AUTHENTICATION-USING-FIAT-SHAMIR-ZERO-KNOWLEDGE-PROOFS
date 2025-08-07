import time
import logging

logger = logging.getLogger('login_performance')

class LoginTimingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path == '/login/' and request.method == 'POST':
            start_time = time.time()
            response = self.get_response(request)
            end_time = time.time()
            elapsed_ms = (end_time - start_time) * 1000  # in milliseconds
            username = request.POST.get("username", "<unknown>")
            auth_type = request.POST.get("auth_type", "<unknown>")
            logger.info(f"Login took {elapsed_ms:.2f} ms for user: {username}, auth_type: {auth_type}")
            return response
        else:
            return self.get_response(request)
