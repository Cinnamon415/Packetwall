/*
 * This file is part of Packetwall (GPL-3.0-or-later).
 * Adapted from PCAPdroid, Copyright 2020-26 Emanuele Faranda, GPL-3.0-or-later.
 * Constructed and updated from native code by name: do not rename the class, its constructor
 * or processUpdate().
 */
package io.github.cinnamon415.packetwall.engine.model;

/** A single network connection as seen by the native engine. Mutated only on the updates thread. */
public class ConnectionDescriptor {
    public static final int CONN_STATUS_NEW = 0,
            CONN_STATUS_CONNECTING = 1,
            CONN_STATUS_CONNECTED = 2,
            CONN_STATUS_CLOSED = 3,
            CONN_STATUS_ERROR = 4,
            CONN_STATUS_SOCKET_ERROR = 5,
            CONN_STATUS_CLIENT_ERROR = 6,
            CONN_STATUS_RESET = 7,
            CONN_STATUS_UNREACHABLE = 8;

    public final int incr_id;
    public final int ipver;
    public final int ipproto;
    public final String src_ip;
    public final String dst_ip;
    public final String country;
    public final int src_port;
    public final int dst_port;
    public final int local_port;
    public final int local_ipver;
    public final int uid;
    public final int ifidx;
    public final boolean mitm_decrypt;

    public long first_seen;
    public long last_seen;
    public long payload_length;
    public long sent_bytes;
    public long rcvd_bytes;
    public int sent_pkts;
    public int rcvd_pkts;
    public int blocked_pkts;
    public int tcp_flags;
    public int status;
    public int error;

    public boolean is_blocked;
    public int fw_rule;
    public boolean proxied;
    public boolean blacklisted_ip;
    public boolean blacklisted_host;
    public boolean netd_block_missed;
    public boolean port_mapping_applied;
    public boolean decryption_ignored;
    public boolean encrypted_l7;

    public String info;
    public String url;
    public String l7proto = "";

    /** Monotonic counter bumped on every update, so the UI can cheaply detect changes. */
    public int version;

    public ConnectionDescriptor(int _incr_id, int _ipver, int _ipproto, String _src_ip, String _dst_ip, String _country,
                                int _src_port, int _dst_port, int _local_port, int _local_ipver, int _uid, int _ifidx,
                                boolean _mitm_decrypt, long when) {
        incr_id = _incr_id;
        ipver = _ipver;
        ipproto = _ipproto;
        src_ip = _src_ip;
        dst_ip = _dst_ip;
        country = _country;
        src_port = _src_port;
        dst_port = _dst_port;
        local_port = _local_port;
        local_ipver = _local_ipver;
        uid = _uid;
        ifidx = _ifidx;
        mitm_decrypt = _mitm_decrypt;
        first_seen = last_seen = when;
    }

    public void processUpdate(ConnectionUpdate update) {
        if ((update.update_type & ConnectionUpdate.UPDATE_STATS) != 0) {
            sent_bytes = update.sent_bytes;
            rcvd_bytes = update.rcvd_bytes;
            sent_pkts = update.sent_pkts;
            rcvd_pkts = update.rcvd_pkts;
            blocked_pkts = update.blocked_pkts;
            status = (update.status & 0x00FF);
            error = (update.status & 0xFF0000) >> 16;
            port_mapping_applied = (update.status & 0x2000) != 0;
            proxied = (update.status & 0x4000) != 0;
            decryption_ignored = (update.status & 0x1000) != 0;
            netd_block_missed = (update.status & 0x0800) != 0;
            is_blocked = (update.status & 0x0400) != 0;
            blacklisted_host = (update.status & 0x0200) != 0;
            blacklisted_ip = (update.status & 0x0100) != 0;
            last_seen = update.last_seen;
            tcp_flags = update.tcp_flags;
            payload_length = update.payload_length;
            fw_rule = update.fw_rule;
        }
        if ((update.update_type & ConnectionUpdate.UPDATE_INFO) != 0) {
            info = update.info;
            url = update.url;
            l7proto = update.l7proto;
            encrypted_l7 = ((update.info_flags & ConnectionUpdate.UPDATE_INFO_FLAG_ENCRYPTED_L7) != 0);
        }
        version++;
    }

    public boolean isActive() {
        return status < CONN_STATUS_CLOSED;
    }
}
