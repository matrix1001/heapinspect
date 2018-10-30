#https://github.com/matrix1001/ezcolor
class Color:
    def __init__(self):
        self._colors = {
                'black': 0,
                'red': 1,
                'green': 2,
                'yellow': 3,
                'blue': 4,
                'magenta': 5,
                'cyan': 6,
                'white': 7,
                }
        self._style = {
                'default': 0,
                'bold': 1,
                'light': 2,
                'on': 3,
                'underline':4,
                'on2': 5,
                }
        self._fg = 30
        self._bg = 40
                
        self.fmt = u'\033[{style};{fg};{bg}m{msg}\033[m'
    def __getattr__(self, attr):
        '''sample: bold_red_bg_blue'''
        style = self._style['default']
        fg = self._colors['white'] + self._fg
        bg = self._colors['black'] + self._bg
        lst = attr.split('_')
        
        ind = 0
        while ind < len(lst):
            if lst[ind] in self._style:
                style = self._style[lst[0]]
            elif lst[ind] in self._colors:
                fg = self._colors[lst[ind]] + self._fg
            elif lst[ind] == 'bg':
                assert ind+1 < len(lst)
                assert lst[ind+1] in self._colors
                color = lst[ind+1]
                bg = self._colors[color] + self._bg
                ind += 1
            else:
                raise Exception('no such color')
            ind += 1
        def format(msg):
            return self.fmt.format(style=style, fg=fg, bg=bg, msg=msg)
        return format
        
color = Color()
if __name__ == '__main__':
    print(color.on_red('test red'))
    print(color.bold_red_bg_white('test 2'))