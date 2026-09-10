#!/usr/bin/env python3
"""
Test D-Bus service for PVCM native_sim testing.

Registers org.pantavisor.TestService on the session bus with:
  - Echo(s) -> s       returns its argument
  - Add(ii) -> i       adds two integers
  - GetInfo() -> a{sv} returns a dict with test info
  - Tick signal        emitted every second with counter

Usage:
  python3 test_dbus_service.py

Requires: python3-dbus (apt install python3-dbus)
"""

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import sys
import time

BUSNAME = "org.pantavisor.TestService"
OBJPATH = "/test"
IFACE = "org.pantavisor.TestService"

tick_counter = 0


class TestService(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, OBJPATH)
        self._start = time.time()

    @dbus.service.method(IFACE, in_signature="s", out_signature="s")
    def Echo(self, message):
        print(f"[test-service] Echo({message!r})")
        return message

    @dbus.service.method(IFACE, in_signature="ii", out_signature="i")
    def Add(self, a, b):
        result = a + b
        print(f"[test-service] Add({a}, {b}) = {result}")
        return result

    @dbus.service.method(IFACE, in_signature="", out_signature="a{sv}")
    def GetInfo(self):
        info = {
            "name": "PVCM Test Service",
            "version": "1.0",
            "uptime": int(time.time() - self._start),
            "pid": dbus.UInt32(42),
        }
        print(f"[test-service] GetInfo() -> {info}")
        return info

    @dbus.service.signal(IFACE, signature="u")
    def Tick(self, counter):
        pass


def emit_tick(service):
    global tick_counter
    tick_counter += 1
    service.Tick(dbus.UInt32(tick_counter))
    return True  # keep timer running


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()

    name = dbus.service.BusName(BUSNAME, bus)
    service = TestService(bus)

    # emit Tick signal every second
    GLib.timeout_add_seconds(1, emit_tick, service)

    print(f"[test-service] {BUSNAME} ready on session bus")
    print(f"[test-service] methods: Echo(s)->s, Add(ii)->i, GetInfo()->a{{sv}}")
    print(f"[test-service] signal: Tick(u) every 1s")

    try:
        GLib.MainLoop().run()
    except KeyboardInterrupt:
        print("\n[test-service] shutting down")


if __name__ == "__main__":
    main()
