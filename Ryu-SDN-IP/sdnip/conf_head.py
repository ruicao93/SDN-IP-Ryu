from ryu import cfg
CONF = cfg.CONF

CONF.register_cli_opts([
    cfg.StrOpt('sdn-ip-cfg-file',
               default="/usr/local/etc/ryu-sdn-ip/config.json",
               help='location of SDN-IP config file')
])

