/*
 * This file is part of Packetwall (GPL-3.0-or-later).
 * Adapted from PCAPdroid, Copyright 2020-26 Emanuele Faranda, GPL-3.0-or-later.
 * Accessed from native code by name: do not rename classes, fields or methods.
 */
package io.github.cinnamon415.packetwall.engine.model;

import java.util.ArrayList;
import java.util.List;

/** Only the descriptor passed to native code; the rule model itself lives in the rules package. */
public class MatchList {
    public static class ListDescriptor {
        public final List<String> apps = new ArrayList<>();
        public final List<String> hosts = new ArrayList<>();
        public final List<String> ips = new ArrayList<>();
        public final List<String> countries = new ArrayList<>();
        public int uid = -1;
        public final List<ListDescriptor> allowlists = new ArrayList<>();
    }
}
