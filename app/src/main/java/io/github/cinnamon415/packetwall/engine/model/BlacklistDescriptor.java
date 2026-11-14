/*
 * This file is part of Packetwall (GPL-3.0-or-later).
 * Adapted from PCAPdroid, Copyright 2020-26 Emanuele Faranda, GPL-3.0-or-later.
 * Accessed from native code by name: do not rename classes, fields or methods.
 */
package io.github.cinnamon415.packetwall.engine.model;

/** A blocklist file loaded by the native engine. */
public class BlacklistDescriptor {
    public enum Type { IP_BLACKLIST, DOMAIN_BLACKLIST }

    public final String fname;
    public final Type type;

    public BlacklistDescriptor(String fname, Type type) { this.fname = fname; this.type = type; }
}
