import fcntl
import termios
import struct


def terminal_size():
    h, w, hp, wp = struct.unpack(
        'HHHH',
        fcntl.ioctl(
            0,
            termios.TIOCGWINSZ,
            struct.pack('HHHH', 0, 0, 0, 0)
            )
        )
    return w, h
