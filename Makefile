bitmaskd:
	twistd -y src/leap/bitmask_core/bitmaskd.tac --pidfile /tmp/bitmaskd.pid --logfile /tmp/bitmaskd.log --umask=0022 -d /tmp/
