import uvicorn
from setting import HOST, PORT, UVICORN_RELOAD

if __name__ == '__main__':
    uvicorn.run('core.config:app', host=HOST, port=PORT, reload=UVICORN_RELOAD)
