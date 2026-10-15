"""Bound request memory before JSON parsing, including chunked ASGI bodies."""
from starlette.responses import JSONResponse


class RequestSizeLimit:
    def __init__(self, app, max_bytes=8 * 1024 * 1024):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        lengths = [value for name, value in scope.get('headers', []) if name.lower() == b'content-length']
        if lengths:
            try:
                if len(lengths) != 1 or not lengths[0].isdigit():
                    raise ValueError('Invalid length')
                length = int(lengths[0])
            except ValueError:
                return await JSONResponse({'detail': 'Invalid Content-Length'}, status_code=400)(scope, receive, send)
            if length > self.max_bytes:
                return await JSONResponse({'detail': 'Request body exceeds 8 MiB limit'}, status_code=413)(scope, receive, send)
        chunks = []
        total = 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            body = message.get('body', b'')
            total += len(body)
            if total > self.max_bytes:
                return await JSONResponse({'detail': 'Request body exceeds 8 MiB limit'}, status_code=413)(scope, receive, send)
            chunks.append(body)
            if not message.get('more_body', False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': b''.join(chunks), 'more_body': False}
            return await receive()

        await self.app(scope, replay, send)
