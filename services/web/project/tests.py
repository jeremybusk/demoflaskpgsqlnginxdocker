import platform


def pre_start_tests():
    test_host_platform()


def post_start_tests():
    pass


def periodic_tests():
    pass


def test_host_platform():
    platform.system()
    platform.release()
    dist = platform.dist()
    dist_code = platform.dist()[2]
    if dist_code == 'bionic' or dist_code == 'buster':
        pass
    else:
        raise SystemExit(f'E: Unsupported host platform {dist}.')
