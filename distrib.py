from unollvm import tasks

if __name__ == '__main__':
    h = tasks.upload_binary('./example/call.fla')
    print tasks.cfg(h)
    print tasks.unflatten(h, 4195600)
