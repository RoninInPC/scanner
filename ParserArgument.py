import argparse

class ParserArgument:
    def __init__(self):
        self.parser = argparse.ArgumentParser()

        groupIP = self.parser.add_mutually_exclusive_group(required=True)
        groupIP.add_argument('-i', '--ip', nargs=1)
        groupIP.add_argument('-n', '--net', nargs=2)

        groupPORT = self.parser.add_mutually_exclusive_group()
        groupPORT.add_argument('-p', '--port', nargs='+', type=int)
        groupPORT.add_argument('-pr', '--port_range', nargs=2, type=int)

        self.parser.add_argument('-s', '--scanner', choices=['syn', 'fin', 'cnt'], default='syn')
        self.parser.add_argument('-th', '-threads', nargs='?', type=int, default=1)
        self.parser.add_argument('-w', '--wait', nargs='?', type=int, default=5)
        self.parser.add_argument('-t', '--timeout', nargs='?', type=int, default=2)

    def getParser(self):
        return self.parser