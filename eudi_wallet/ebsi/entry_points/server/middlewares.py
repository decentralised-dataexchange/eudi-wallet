from aiohttp import web

from eudi_wallet.ebsi.entry_points.server.utils import get_app_context


async def logging_middleware(app, handler):
    async def middleware_handler(request):
        app_context = get_app_context(app)
        logger = app_context.logger

        assert logger is not None

        # Log the request
        logger.debug(f"Received request: {request.method} {request.path}")

        # Log the query params
        query_params = request.rel_url.query
        if query_params:
            logger.debug(f"Query parameters: {query_params}")

        # Read and log the payload
        if request.body_exists:
            if request.headers.get("Content-Type") == "application/json":
                try:
                    body = await request.json()
                    logger.debug(f"Payload: {body}")
                except Exception as e:
                    logger.error(f"Error parsing JSON payload: {e}")
            elif (
                request.headers.get("Content-Type")
                == "application/x-www-form-urlencoded"
            ):
                try:
                    body = await request.post()
                    logger.debug(f"Form payload: {body}")
                except Exception as e:
                    logger.error(f"Error parsing form payload: {e}")
        # Call the next middleware or route handler
        response = await handler(request)
        return response

    return middleware_handler


async def error_middleware(app, handler):
    async def middleware_handler(request):
        app_context = get_app_context(app)
        logger = app_context.logger

        assert logger is not None

        try:
            # Call the next middleware or route handler
            response = await handler(request)
            return response
        except web.HTTPException:
            # Re-raise the exception so aiohttp can handle it
            raise
        except Exception as ex:
            # Log the exception
            logger.debug(f"Caught exception: {type(ex).__name__}: {ex}")
            # Return a HTTP 500 error to the client
            return web.json_response(
                {"error": "An error occurred on the server."}, status=500
            )

    return middleware_handler
