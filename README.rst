bitmask-core
============

*temporary* repository, code experiments.

towards a **bitmask.core** + **bitmask.cli** transition.

this should not be a package on its own, rather I envision that it can be moved
to sub-modules inside the bitmask package.

the package for bitmask would have an optional extra,
`bitmask.gui`, depending on qt, and that could probably be packaged as a different
debian package.

Using
-----

ok, we told you this is unsupported software, and you still want to play with it.
This can get you running::

  make bitmaskd_server
  bitmask_cli --help


Design principles 
-----------------

In the beginning, bitmask was the only user of all the libraries that make the
client-side LEAP ecosystem.

All the development of the Bitmask client turned around the Qt libraries, since
this was all that was needed to run a multiplatform client in python.

However, this has changed, and we now want to support different scenarios:

* Headless client, controllable from command line or a curses/urwid client.
* Ability to select just some of the available modules to be run (ie,
  VPN, mail, ...)
* Make all the common bootstrapping process, as long as the
  Authentication services available to other clientside LEAP services that
  depend on it (without needing all the qt-deps).
* Multi-user scenarios.

In a nutshell, that's why we are experimenting with service composition.

* bitmask-core should be an standalone daemon, that we can run at startup time.
* bitmask-cli can execute commands against it, wait for the result, and display
  it to the user.

Things to think about
---------------------

Any client sending commands to the core should be able to authenticate itself,
specially when the core is handling several soledad users.

we should think about an authentication system to restrict permissions to one
user per client (local tokens?).

this can be reused, for instance, to issue per-user tokens to be used in
authentication for other services (think IMAP, or the thunderbird plugin for
instance).

