/*
 * This file is part of Packetwall (GPL-3.0-or-later).
 * Adapted from PCAPdroid, Copyright 2020-26 Emanuele Faranda, GPL-3.0-or-later.
 * Accessed from native code by name: do not rename classes, fields or methods.
 */
package io.github.cinnamon415.packetwall.engine;

public class Blacklists {
    public static class NativeBlacklistStatus {
        public final String fname;
        public final int num_rules;

        public NativeBlacklistStatus(String fname, int num_rules) { this.fname = fname; this.num_rules = num_rules; }
    }
}
