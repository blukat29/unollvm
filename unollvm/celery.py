from __future__ import absolute_import
from celery import Celery

app = Celery('unollvm',
        broker='redis://localhost',
        backend='redis://localhost',
        include=['unollvm.tasks'])

if __name__ == '__main__':
    app.start()
