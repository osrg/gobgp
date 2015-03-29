import os
from nose.plugins import Plugin

parser_option = None


class OptionParser(Plugin):

    def options(self, parser, env=os.environ):
        super(OptionParser, self).options(parser, env=env)
        parser.add_option('--use-local', action="store_true", dest="use_local", default=False)
        parser.add_option('--exabgp-path', action="store", dest="exabgp_path", default="")
        parser.add_option('--go-path', action="store", dest="go_path", default="")
        parser.add_option('--gobgp-log-debug', action="store_true", dest="gobgp_log_debug", default=False)

    def configure(self, options, conf):
        super(OptionParser, self).configure(options, conf)
        global parser_option
        parser_option = options

        if not self.enabled:
            return

    def finalize(self, result):
        pass